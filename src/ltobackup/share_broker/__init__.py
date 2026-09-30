"""Narrow privileged boundary for read-only managed network sources."""

from .client import ShareBrokerClient, ShareBrokerUnavailable
from .protocol import ShareMountReceiptV1

__all__ = ["ShareBrokerClient", "ShareBrokerUnavailable", "ShareMountReceiptV1"]
