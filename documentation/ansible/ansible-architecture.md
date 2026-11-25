# Ansible source-example packaging contract

This reference covers only consumer example availability in source
distributions. Runtime integration boundaries remain documented in
[the Ansible API guide](../../docs/api/ansible.md).

The setuptools source manifest explicitly includes exactly these existing
consumer files:

- `examples/ansible/collect_facts.yml`
- `examples/ansible/inventory.yaml`
- `examples/ansible/run_commands.yml`

They belong beneath `examples/ansible/` in the extracted sdist, making the
samples available without a repository checkout. The selection uses explicit
file directives, not a broad examples/source glob or private-artifact inclusion.
This contract does not promise wheel-installed examples or change runtime
package discovery, versioning or release workflows.

Source selection is not proof of rebuilt archive contents, installation,
controller readiness, example execution, artifact authenticity or complete
Ansible/Molecule/platform qualification. Separate tester-owned archive and
outside-checkout checks remain required; retained failed artifacts and
assertions are not superseded by this source repair.

The separate source-only dedicated verifier launch contract is recorded in
[Nov22 verifier context](nov22-verifier-context-architecture.md). It preserves
the existing runtime trust limits and does not constitute execution acceptance.
