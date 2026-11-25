"""Build a local bare Git snapshot inside a new protected publication only."""

from __future__ import annotations

import hashlib
import zlib


def snapshot_files(content: bytes, receipt: bytes) -> dict[str, bytes]:
    """Encode valid Git objects without hooks, user configuration or processes.

    Every returned path belongs to the new artifact's private git directory.
    No existing repository is opened, staged, committed, configured or pushed.
    """
    files: dict[str, bytes] = {}

    def put(kind: str, value: bytes) -> str:
        raw = kind.encode("ascii") + b" " + str(len(value)).encode("ascii") + b"\0" + value
        # Git's object format is SHA-1; this is not a protection/content identity.
        identity = hashlib.sha1(raw).hexdigest()
        files["objects/" + identity[:2] + "/" + identity[2:]] = zlib.compress(raw)
        return identity

    content_id, receipt_id = put("blob", content), put("blob", receipt)
    tree = put("tree", b"100644 content\0" + bytes.fromhex(content_id)
               + b"100644 receipt.json\0" + bytes.fromhex(receipt_id))
    commit = put("commit", (
        "tree " + tree + "\nauthor NetOps <netops@localhost> 0 +0000\n"
        "committer NetOps <netops@localhost> 0 +0000\n\nExplicit protected artifact\n"
    ).encode("ascii"))
    files.update({
        "HEAD": b"ref: refs/heads/artifacts\n",
        "refs/heads/artifacts": (commit + "\n").encode("ascii"),
        "config": b"[core]\n\trepositoryformatversion = 0\n\tbare = true\n",
    })
    return files
