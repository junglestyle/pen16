import pytest
from defusedxml import EntitiesForbidden

from pen15 import nmap


def test_entity_expansion_is_refused() -> None:
    hostile = b"""<?xml version="1.0"?>
<!DOCTYPE nmaprun [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
<nmaprun version="7.94SVN">&b;</nmaprun>"""

    with pytest.raises(EntitiesForbidden):
        nmap.parse(hostile)
