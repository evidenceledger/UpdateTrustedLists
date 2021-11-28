# UpdateTrustedLists

## Installation

In the parent directory of the webapp:

    git clone git@github.com:evidenceledger/UpdateTrustedLists.git
    cd UpdateTrustedLists
    poetry install

## Updating the Trusted Lists

In the `UpdateTrustedLists` directory:

    poetry shell
    python gpk.py update-verificacovid
    python gpk.py update-mycovidcredential
