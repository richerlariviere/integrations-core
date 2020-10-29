# (C) Datadog, Inc. 2020-present
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
import pytest

from .conftest import get_ssl

ssl_enabled = pytest.mark.skipif(not get_ssl(), reason='Test can only be run on SSL-enabled instances of Zookeeper')

not_ssl_enabled = pytest.mark.skipif(get_ssl(), reason='Test can only be run on non SSL-enabled instances of Zookeeper')
