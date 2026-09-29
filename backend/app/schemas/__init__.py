"""Pydantic contracts, in two layers.

``raw``
    What the upstream systems emit, one shape per source. Used only by ingestion.

``domain``
    The normalised model. This is the *only* shape the security engine sees, so
    the engine never has to know whether an action came from CloudTrail, GitHub
    or a proxy.
"""
