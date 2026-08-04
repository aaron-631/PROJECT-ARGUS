"""Deliberately unsafe code used only by the Argus example fixture."""

import pickle
import subprocess


def run_user_workflow(value: str) -> object:
    result = eval(value)  # noqa: S307 - intentional scanner fixture
    subprocess.run(value, shell=True, check=False)  # noqa: S602 - intentional fixture
    return pickle.loads(result)  # noqa: S301 - intentional fixture
