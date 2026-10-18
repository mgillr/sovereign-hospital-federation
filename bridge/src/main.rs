// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Ryan Gillespie / Optitransfer
//! acfa-bridge: stdin JSON -> stdout JSON. Subcommands:
//!   pubkey   {node_id, secret}                                   -> {node_id, pubkey}
//!   sign     {node_id, secret, ctx, round, f, tensor:[i64]}      -> contribution
//!   issue    {pki, ctx, round, f, contributions, out, out_redacted} -> resolution summary
//!   root     {pki, round, contributions}                         -> {state_root}
//!   resolve  {pki, ctx, round, f, receipt_path}                  -> verified aggregate
//! Secrets travel on stdin only. All arithmetic, hashing and signing is acfa-rs code.
use acfa_receipt::hash::{enc_tensor, h};
use acfa_receipt::identity::{contrib_msg, Identity, Pki, PreimageVersion};
use acfa_receipt::{decode, encode_checked, Contribution, Policy, Receipt, RoundParams, Rule, State};
use serde_json::{json, Value};
use std::io::Read;

fn hx(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 || !s.is_ascii() { return Err(format!("bad hex len {}", s.len())); }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}
fn arr<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let v = unhex(s)?; v.try_into().map_err(|_| format!("expected {N} bytes"))
}
fn get<'a>(v: &'a Value, k: &str) -> Result<&'a Value, String> { v.get(k).ok_or(format!("missing field {k}")) }
fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> { get(v, k)?.as_str().ok_or(format!("{k} not a string")) }
fn u(v: &Value, k: &str) -> Result<u64, String> { get(v, k)?.as_u64().ok_or(format!("{k} not u64")) }
fn params(f: u64) -> RoundParams { RoundParams::new(Rule::Krum, f as u32) }

fn pki_of(v: &Value) -> Result<Pki, String> {
    let mut p = Pki::new();
    for e in get(v, "pki")?.as_array().ok_or("pki not array")? {
        let id = e[0].as_u64().ok_or("pki id")? as u32;
        p.insert(id, arr::<32>(e[1].as_str().ok_or("pki key")?)?);
    }
    Ok(p)
}
fn contrib_of(c: &Value) -> Result<Contribution, String> {
    let tensor: Vec<i64> = get(c, "tensor")?.as_array().ok_or("tensor")?.iter()
        .map(|x| x.as_i64().ok_or("tensor value not i64".to_string())).collect::<Result<_, _>>()?;
    Ok(Contribution {
        ctx: arr::<32>(s(c, "ctx")?)?,
        sig_preimage: PreimageVersion::V2,
        params: params(u(c, "f")?),
        rnd: u(c, "round")?,
        node_id: u(c, "node_id")? as u32,
        tensor,
        sig: arr::<64>(s(c, "sig")?)?,
    })
}
fn state_of(v: &Value, pki: &Pki) -> Result<State, String> {
    let mut st = State::new();
    for c in get(v, "contributions")?.as_array().ok_or("contributions")? { st.deliver(contrib_of(c)?, pki); }
    Ok(st)
}

fn run(cmd: &str, v: Value) -> Result<Value, String> {
    match cmd {
        "pubkey" => {
            let id = Identity::from_secret(u(&v, "node_id")? as u32, &arr::<32>(s(&v, "secret")?)?);
            Ok(json!({"node_id": id.node_id, "pubkey": hx(&id.public())}))
        }
        "sign" => {
            let id = Identity::from_secret(u(&v, "node_id")? as u32, &arr::<32>(s(&v, "secret")?)?);
            let ctx = arr::<32>(s(&v, "ctx")?)?;
            let round = u(&v, "round")?; let f = u(&v, "f")?;
            let tensor: Vec<i64> = get(&v, "tensor")?.as_array().ok_or("tensor")?.iter()
                .map(|x| x.as_i64().ok_or("tensor value not i64".to_string())).collect::<Result<_, _>>()?;
            let th = h(&enc_tensor(&tensor));
            let sig = id.sign(&contrib_msg(&ctx, &params(f), round, id.node_id, &th));
            let c = Contribution { ctx, sig_preimage: PreimageVersion::V2, params: params(f), rnd: round,
                node_id: id.node_id, tensor: tensor.clone(), sig };
            Ok(json!({"node_id": id.node_id, "ctx": hx(&ctx), "round": round, "f": f, "tensor": tensor,
                "tensor_hash": hx(&th), "sig": hx(&sig), "leaf": hx(&c.leaf())}))
        }
        "root" => {
            let pki = pki_of(&v)?; let st = state_of(&v, &pki)?;
            Ok(json!({"state_root": hx(&st.root())}))
        }
        "issue" => {
            let pki = pki_of(&v)?; let st = state_of(&v, &pki)?;
            let ctx = arr::<32>(s(&v, "ctx")?)?; let round = u(&v, "round")?; let f = u(&v, "f")? as usize;
            let r = Receipt::issue(&st, ctx, round, &pki, f, Rule::Krum);
            let bytes = encode_checked(&r).map_err(|e| format!("encode: {e:?}"))?;
            std::fs::write(s(&v, "out")?, &bytes).map_err(|e| e.to_string())?;
            if let Some(p) = v.get("out_redacted").and_then(|x| x.as_str()) {
                std::fs::write(p, acfa_receipt::wire::encode_redacted(&r.redact())).map_err(|e| e.to_string())?;
            }
            // Selection report: the SAME kernel call resolve() makes (multi-Krum over the admitted
            // set, leaf tie keys), so the reported kept/dropped set is the one the aggregate used.
            let adm = st.admit(round, &pki);
            let cs: Vec<acfa_aggregate::Contribution> = adm.iter()
                .map(|c| acfa_aggregate::Contribution { tie_key: c.leaf().to_vec(), v: c.tensor.clone() }).collect();
            let sel: Vec<u32> = acfa_aggregate::multi_krum(&cs, f).map_err(|e| format!("{e:?}"))?
                .into_iter().map(|i| adm[i].node_id).collect();
            let ver = r.verify(&Policy::new(pki.clone(), f).expecting(Rule::Krum).about(ctx)
                .with_max_coordinates(50_000_000)).map_err(|e| format!("self-verify failed: {e:?}"))?;
            let check = acfa_aggregate::krum_aggregate(&cs, f).map_err(|e| format!("{e:?}"))?;
            if Some(&check) != ver.aggregate.as_ref() { return Err("selection report disagrees with receipt aggregate".into()); }
            Ok(json!({"bytes": bytes.len(), "state_root": hx(&ver.state_root), "output_root": hx(&ver.output_root),
                "admitted": ver.admitted, "selected": sel, "convicted": ver.convicted,
                "population_bound_met": ver.population_bound_met,
                "no_flip_certified": ver.margin.as_ref().map(|m| m.certified),
                "aggregate": ver.aggregate}))
        }
        "resolve" => {
            let pki = pki_of(&v)?; let ctx = arr::<32>(s(&v, "ctx")?)?; let f = u(&v, "f")? as usize;
            let bytes = std::fs::read(s(&v, "receipt_path")?).map_err(|e| e.to_string())?;
            let r = decode(&bytes).map_err(|e| format!("decode: {e:?}"))?;
            if r.round != u(&v, "round")? { return Err(format!("round mismatch: receipt {}", r.round)); }
            let ver = r.verify(&Policy::new(pki, f).expecting(Rule::Krum).about(ctx).with_max_coordinates(50_000_000))
                .map_err(|e| format!("invalid: {e:?}"))?;
            Ok(json!({"state_root": hx(&ver.state_root), "output_root": hx(&ver.output_root),
                "admitted": ver.admitted, "convicted": ver.convicted, "aggregate": ver.aggregate}))
        }
        _ => Err(format!("unknown command {cmd}")),
    }
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("stdin");
    let out = serde_json::from_str::<Value>(&input).map_err(|e| e.to_string()).and_then(|v| run(&cmd, v));
    match out {
        Ok(v) => { println!("{v}"); }
        Err(e) => { println!("{}", json!({"error": e})); std::process::exit(1); }
    }
}
