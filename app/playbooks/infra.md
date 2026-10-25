# Surface: Infrastructure, CI/CD and dependencies
Checklist
- GitHub Actions / CI: mutable action tags vs pinned SHAs (especially in deploy/publish workflows), pull_request_target misuse, secrets exposed to forks, overly broad permissions:, script injection via ${{ github.event.* }} in run: steps, self-hosted runner trust.
- Containers: Dockerfiles running as root, latest tags, secrets in build args or layers, --omit=dev missing, exposed debug ports; compose files with host mounts.
- IaC: CDK/Terraform/CloudFormation/Amplify with wildcard IAM, public S3, open security groups, unencrypted storage, hard-coded account ids or keys.
- Dependency reachability: for each High/Critical advisory from npm audit / pip-audit / cargo audit, determine whether the package is a runtime dependency (dependencies vs devDependencies, imported on request paths) or dev/test only. Downgrade dev-only CVEs to low and say why. Check for lockfiles missing in sub-packages (Lambda functions, cdk/, packages/*).
- Package publishing: .npmrc tokens, publish workflows, scope ownership, provenance.
- Secrets hygiene: .env/.envrc committed, example files with real values, credentials in git history (use git_log on suspicious files), test fixtures that are actually live keys.
- Supply chain: --extra-index-url, curl | sh in Dockerfiles/scripts, unpinned base images, postinstall scripts.
Output: prefer a small number of high-value findings with exact file:line over listing every unpinned action; aggregate repeated patterns into one finding with the count and the worst instance.
