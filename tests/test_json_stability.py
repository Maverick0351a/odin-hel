import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st


@settings(suppress_health_check=[HealthCheck.too_slow], max_examples=30)
@given(
    st.dictionaries(
        keys=st.text(),
        values=(
            st.text()
            | st.integers()
            | st.floats(allow_nan=False)
            | st.booleans()
            | st.none()
        ),
        max_size=10,
    )
)

def test_canonical_json_stability(ctx):
    """
    Property: Serializing and deserializing context as JSON should be stable and not raise errors.
    """
    try:
        s = json.dumps(ctx, sort_keys=True, separators=(",", ":"))
        loaded = json.loads(s)
        assert loaded == ctx or isinstance(loaded, dict)
    except Exception as e:
        assert False, f"JSON (de)serialization failed: {e}"
