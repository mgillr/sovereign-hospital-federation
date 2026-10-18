# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ryan Gillespie / Optitransfer
import os, sys, pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

@pytest.fixture(scope="session")
def fed_dp(tmp_path_factory):
    from fed.federation import Federation
    f = Federation(tmp_path_factory.mktemp("fed_dp"), seed=7, adversary="poison", dp=True)
    f.setup()
    f.run_rounds(3)
    return f

@pytest.fixture(scope="session")
def fed_nodp(tmp_path_factory):
    from fed.federation import Federation
    f = Federation(tmp_path_factory.mktemp("fed_nodp"), seed=7, adversary="poison", dp=False)
    f.setup()
    f.run_rounds(3)
    return f

@pytest.fixture(scope="session")
def blind_dp(tmp_path_factory):
    from fed.federation import Federation
    f = Federation(tmp_path_factory.mktemp("blind_dp"), seed=7, mode="blind", adversary="sign-flip-in-bound", dp=True)
    f.setup(); f.run_rounds(3)
    return f

@pytest.fixture(scope="session")
def blind_poison_nodp(tmp_path_factory):
    from fed.federation import Federation
    f = Federation(tmp_path_factory.mktemp("blind_poison"), seed=7, mode="blind", adversary="poison", dp=False)
    f.setup(); f.run_rounds(2)
    return f

@pytest.fixture(scope="session")
def attacks(fed_dp):
    from fed.federation import privacy_attacks
    return privacy_attacks(fed_dp, None)

@pytest.fixture(scope="session")
def bundle(fed_dp, attacks, tmp_path_factory):
    a, sh = attacks
    return fed_dp.build_bundle(tmp_path_factory.mktemp("bundle") / "evidence.zip", a, sh)

@pytest.fixture(scope="session")
def blind_bundle(blind_dp, tmp_path_factory):
    return blind_dp.build_bundle(tmp_path_factory.mktemp("bbundle") / "evidence.zip")
