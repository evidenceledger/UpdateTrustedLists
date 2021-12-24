# UpdateTrustedLists

## Installation

This repository should be a sibling of the VerificaCOVID and MyCOVIDCredential repositories.
In the parent directory of the webapp (the one where VerificaCOVID and MyCOVIDCredential are located):

    git clone git@github.com:evidenceledger/UpdateTrustedLists.git
    cd UpdateTrustedLists
    poetry install

## Updating the Trusted Lists

In the `UpdateTrustedLists` directory:

    poetry shell
    python gpk.py update-verificacovid
    python gpk.py update-mycovidcredential

