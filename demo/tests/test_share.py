"""Share-rebuild unit tests — the pure, security-relevant bits.

The typeahead query feeds a PostgREST or() filter whose grouping is structural
(commas/parentheses), so an unsanitized query is a filter-injection vector.
clean_search_query must strip anything that could break out of the group.
"""
import app


def test_clean_search_query_strips_filter_metacharacters():
    # Commas and parentheses (PostgREST or() structure) must not survive.
    assert "," not in app.clean_search_query("a,b")
    assert "(" not in app.clean_search_query("x(y)")
    assert ")" not in app.clean_search_query("x(y)")
    # A real injection attempt collapses to inert text.
    dirty = "*,id.eq.00000000-0000-0000-0000-000000000000)"
    cleaned = app.clean_search_query(dirty)
    assert "(" not in cleaned and ")" not in cleaned and "," not in cleaned and "*" not in cleaned


def test_clean_search_query_keeps_legit_input():
    assert app.clean_search_query("  Mark Turner ") == "Mark Turner"
    assert app.clean_search_query("mark.turner+test@xinsere.com") == "mark.turner+test@xinsere.com"
    assert app.clean_search_query("") == ""
    assert len(app.clean_search_query("x" * 200)) == 64  # bounded
