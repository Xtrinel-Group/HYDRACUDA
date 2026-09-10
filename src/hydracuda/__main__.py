"""`python -m hydracuda` — the same CLI as the `hydracuda` console script.

Worth having its own module because the compiled binary is named `hcuda` and its
error message for `HYDRACUDA_ENGINE=python` tells the reader to run
`python -m hydracuda test`. That instruction has to work on a machine where the
console script was never put on `PATH`, which is exactly the machine where
someone is reaching for the module form.
"""

from hydracuda.cli import main

if __name__ == "__main__":
    main()
