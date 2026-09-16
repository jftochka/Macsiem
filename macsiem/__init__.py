"""MacSIEM - 24/7/365 macOS monitoring and 360-degree evidence platform.

Built around the LOOBins corpus (https://loobins.io): 62 native macOS binaries
that adversaries live off of.  MacSIEM turns that catalogue into (a) continuous
detection and (b) an all-binaries-at-once, read-only evidence sweep.

Standard library only.  No third-party dependencies, ever: the agent has to run
on a stock macOS `python3` with no network and no `pip install`.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
