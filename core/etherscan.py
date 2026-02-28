"""Etherscan API integration for fetching contract source code."""
import os
import httpx

CHAIN_APIS = {
    "ethereum": "https://api.etherscan.io/api",
    "bsc": "https://api.bscscan.com/api",
    "polygon": "https://api.polygonscan.com/api",
    "arbitrum": "https://api.arbiscan.io/api",
}


def fetch_contract_source(address: str, chain: str = "ethereum") -> str:
    api_key = os.getenv("ETHERSCAN_API_KEY", "")
    base_url = CHAIN_APIS.get(chain, CHAIN_APIS["ethereum"])

    response = httpx.get(
        base_url,
        params={
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": api_key,
        },
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()

    if data["status"] != "1" or not data["result"][0]["SourceCode"]:
        raise ValueError(f"Contract source not found for {address} on {chain}")

    return data["result"][0]["SourceCode"]
