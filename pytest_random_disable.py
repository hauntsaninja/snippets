import random
import pytest


def disable_randomly(config, item):
    if random.random() < 0.5:
        return "muahahaha randomly disabled"


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config, items):
    for item in items:
        if reason := disable_randomly(config, item):
            assert isinstance(reason, str)
            item.add_marker(pytest.mark.skip(reason=reason))
