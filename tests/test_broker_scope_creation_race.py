"""Reconciliation must not overtake an authenticated scope creation."""

import os
import threading
import unittest
from unittest.mock import patch

from ltobackup.broker.protocol import decode_response, encode_request
from ltobackup.broker.service import CommandBrokerService
from tests.test_broker_service import CAPABILITY, PROOF_KEY, _MemoryCgroup, _MemoryStore, _send


class ScopeCreationRaceTests(unittest.TestCase):
    def test_open_waits_for_creation_delayed_in_nonce_commit(self):
        self._race("nonce")

    def test_open_waits_for_physical_scope_binding(self):
        self._race("cgroup")

    def test_failed_creation_is_not_treated_as_reconciled(self):
        self._race("nonce", fail_creation=True)

    def _race(self, boundary, *, fail_creation=False):
        store = _MemoryStore()
        cgroup = _MemoryCgroup(store)
        service = CommandBrokerService(
            store, cgroup, capability=CAPABILITY, proof_key=PROOF_KEY,
            daemon_uid=os.getuid(), daemon_gid=os.getgid(), enforcing=False,
            daemon_context="system_u:system_r:lto_archiver_t:s0",
        )
        entered = threading.Event()
        proceed = threading.Event()
        open_authenticated = threading.Event()
        open_finished = threading.Event()
        results = {}
        errors = []
        original_auth = service._authenticate_peer
        original_nonce = store.record_nonce
        original_create = cgroup.create

        def barrier():
            entered.set()
            if not proceed.wait(3):
                raise AssertionError("creation barrier was not released")

        def nonce(domain, value):
            result = original_nonce(domain, value)
            if boundary == "nonce" and domain == "create_scope" and not entered.is_set():
                barrier()
                if fail_creation:
                    from ltobackup.broker.store import BrokerStateUnavailable
                    raise BrokerStateUnavailable
            return result

        def create(record, state):
            if boundary == "cgroup":
                barrier()
            return original_create(record, state)

        def authenticate(connection, method):
            original_auth(connection, method)
            if method == "open_scope":
                open_authenticated.set()

        def request(method, identity):
            try:
                packet = encode_request(
                    method, request_id=identity * 32, capability=CAPABILITY,
                    params={"command_id": "delayed-create", "owner_generation": 185,
                            "request_nonce": identity.upper() * 32},
                )
                results[method] = decode_response(_send(service, packet))
            except BaseException as exc:
                errors.append(exc)
            finally:
                if method == "open_scope":
                    open_finished.set()

        creator = threading.Thread(target=request, args=("create_scope", b"c"))
        opener = threading.Thread(target=request, args=("open_scope", b"o"))
        with patch.object(store, "record_nonce", side_effect=nonce), \
             patch.object(cgroup, "create", side_effect=create), \
             patch.object(service, "_authenticate_peer", side_effect=authenticate):
            try:
                creator.start()
                self.assertTrue(entered.wait(3))
                opener.start()
                self.assertTrue(open_authenticated.wait(3))
                self.assertFalse(open_finished.wait(0.15), "recovery overtook unfinished creation")
            finally:
                proceed.set()
                creator.join(3)
                if opener.ident is not None:
                    opener.join(3)
        self.assertFalse(creator.is_alive())
        self.assertFalse(opener.is_alive())
        self.assertEqual([], errors)
        if fail_creation:
            self.assertIsNotNone(results["create_scope"].error_code)
            self.assertIsNotNone(results["open_scope"].error_code)
            self.assertEqual({}, store.scopes)
            return
        self.assertIsNone(results["create_scope"].error_code)
        self.assertIsNone(results["open_scope"].error_code)
        self.assertEqual(results["create_scope"].result["receipt"]["scope_id"],
                         results["open_scope"].result["receipt"]["scope_id"])
        self.assertIsNone(store.scope_for_identity("delayed-create", 185).pid)
