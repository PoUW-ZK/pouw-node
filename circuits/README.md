# circuits

Circom sources of the task catalog: the circuits clients ask the network to prove.
The directory is owned together with @Quolen.

Every circuit exposes `eta` and `mask` as its first two public inputs, followed by the
client inputs. Generated artefacts (`*.r1cs`, `*.zkey`, `*.ptau`, `*.sym`) are not
committed, see `.gitignore`.

Layout of one circuit:

```text
circuits/<name>/<name>.circom   the circuit
circuits/<name>/README.md       what it proves, public inputs, constraint count
```
