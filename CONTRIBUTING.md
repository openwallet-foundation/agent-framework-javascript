## How to contribute

You are encouraged to contribute to the repository by **forking and submitting a pull request**.

(If you are new to GitHub, you might start with a [basic tutorial](https://help.github.com/articles/set-up-git) and check out a more detailed guide to [pull requests](https://help.github.com/articles/using-pull-requests/).)

Pull requests will be evaluated by the repository guardians on a schedule and if deemed beneficial will be committed to the main branch. Pull requests should have a descriptive name and include an summary of all changes made in the pull request description.

If you would like to propose a significant change, please open an issue first to discuss the proposed changes with the community and to avoid re-work.

Contributions are made pursuant to the Developer's Certificate of Origin, available at [https://developercertificate.org](https://developercertificate.org), and licensed under the Apache License, version 2.0 (Apache-2.0).

## Contributing checklist:

- It is difficult to manage a release with too many changes.
  - We should **release more often**, not months apart.
  - We should focus on feature releases (minor and patch releases) to speed iteration.
    - See our [Credo Docs on semantic versioning](https://credo.js.org/guides/updating#versioning). Notably, while our versions are pre 1.0.0, minor versions are breaking change versions.
- Mixing breaking changes with other PRs slows development.
  - Non-breaking change PRs are merged earlier into **main**
  - Breaking change PRs will go to a branch named **<release-version>-pre (ie. 0.3.0-pre)** and merged later in the release cycle.
  - Consider separating your PR into a (usually larger) non-breaking PR and a (usually smaller) breaking change PR.
- Relevant changes for the changelog must be documented using changesets. See [Changesets](.changeset/README.md) for more info. To add a changelog, run `pnpm changeset` and commit the files afterwards.
