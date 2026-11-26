"""RC-1 primitives: hostile shapes are refused with MalformedInput; benign pass."""
import pytest

from secprim.boundary import (MalformedInput, as_dict, as_list, as_str,
                              finite_float, contained_path)


def test_as_dict_accepts_dict_and_refuses_others():
    assert as_dict({"a": 1}, "p") == {"a": 1}
    assert as_dict(None, "p", optional=True) == {}
    for bad in (None, "str", [1], 3, 1.5, True):
        with pytest.raises(MalformedInput) as e:
            as_dict(bad, "form.controls")
        assert "form.controls" in str(e.value)


def test_as_list_refuses_str_even_though_iterable():
    assert as_list([1, 2], "p") == [1, 2]
    assert as_list(None, "p", optional=True) == []
    with pytest.raises(MalformedInput):
        as_list("not-a-list", "p")
    with pytest.raises(MalformedInput):
        as_list({"a": 1}, "p")


def test_as_str_type_length_and_nul():
    assert as_str("ok", "p") == "ok"
    assert as_str(None, "p", optional=True) == ""
    with pytest.raises(MalformedInput):
        as_str(5, "p")
    with pytest.raises(MalformedInput):
        as_str("x" * 11, "p", max_len=10)
    with pytest.raises(MalformedInput):
        as_str("a\x00b", "p")


@pytest.mark.parametrize("good,expected", [(1.5, 1.5), ("2.0", 2.0), (3, 3.0), (" 4 ", 4.0), (-7, -7.0)])
def test_finite_float_accepts_real_numbers(good, expected):
    assert finite_float(good, "marginal_cost") == expected


@pytest.mark.parametrize("bad", ["nan", "inf", "-inf", "1e999", float("nan"), float("inf"),
                                 True, "abc", None, [1], {"a": 1}])
def test_finite_float_refuses_non_finite_and_wrong_types(bad):
    with pytest.raises(MalformedInput):
        finite_float(bad, "marginal_cost")


def test_finite_float_bounds():
    assert finite_float(24, "hours", lo=1, hi=168) == 24.0
    with pytest.raises(MalformedInput):
        finite_float(0, "hours", lo=1)
    with pytest.raises(MalformedInput):
        finite_float(169, "hours", hi=168)


def test_contained_path_keeps_legit_paths_and_refuses_escapes(tmp_path):
    root = tmp_path / "course"
    root.mkdir()
    ok = contained_path(root, "files/notes.pdf")
    assert ok == root / "files/notes.pdf"
    # a '..' that stays inside is fine
    assert contained_path(root, "files/../a.txt") == root / "files/../a.txt"
    for bad in ("../outside.txt", "files/../../x", "/etc/passwd", "\\abs", "C:x", "a\x00b", ""):
        with pytest.raises(MalformedInput):
            contained_path(root, bad)
    with pytest.raises(MalformedInput):
        contained_path(root, 42)
