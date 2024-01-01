def is_within_edit_distance(a: str, b: str, distance: int) -> int | None:
    if len(a) > len(b):
        a, b = b, a
    if len(b) - len(a) > distance:
        return None
    distance = min(distance, len(b))

    # TODO: compare to top-down
    grid: list[list[int]] = [[None] * (2 * distance + 1) for _ in range(len(a) + 1)]  # type: ignore
    # grid[ai][distance + bi - ai] = lev(a[ai:], b[bi:])
    for gbi in range(2 * distance + 1):
        bi = len(a) + gbi - distance
        if 0 <= bi <= len(b):  # not necessary
            grid[len(a)][gbi] = len(b) - bi
    for ai in range(len(a)):
        gbi = distance + len(b) - ai
        if gbi < len(grid[ai]):
            grid[ai][gbi] = len(a) - ai

    for ai in reversed(range(len(a))):
        early_exit = True
        for bi in reversed(range(max(0, ai - distance), min(len(b), ai + distance + 1))):
            # assert abs(ai - bi) <= distance
            gbi = distance + bi - ai
            val = grid[ai + 1][gbi]  # lev(ai + 1, bi + 1)
            if a[ai] != b[bi]:
                rma = grid[ai + 1][gbi - 1] if gbi - 1 >= 0 else distance  # lev(ai + 1, bi)
                rmb = grid[ai][gbi + 1] if gbi + 1 < len(grid[ai]) else distance  # lev(ai, bi + 1)
                val = 1 + min(val, rma, rmb)

            if val <= distance:
                early_exit = False
            grid[ai][gbi] = val

        if early_exit:
            return None

    edit_distance = grid[0][distance]
    if edit_distance <= distance:
        return edit_distance
    return None


def test_is_within_edit_distance() -> None:
    # Test identical strings
    assert is_within_edit_distance("hello", "hello", 0) == 0
    assert is_within_edit_distance("hello", "hello", 1) == 0
    assert is_within_edit_distance("hello", "hello", 100) == 0

    # Test empty strings
    assert is_within_edit_distance("", "", 0) == 0
    assert is_within_edit_distance("", "", 1) == 0
    assert is_within_edit_distance("", "a", 1) == 1
    assert is_within_edit_distance("a", "", 1) == 1

    # Test one operation away
    assert is_within_edit_distance("a", "ab", 1) == 1  # Insertion
    assert is_within_edit_distance("ab", "a", 1) == 1  # Deletion
    assert is_within_edit_distance("a", "b", 1) == 1  # Substitution

    # Test multiple operations
    assert is_within_edit_distance("kitten", "sitting", 3) == 3
    assert is_within_edit_distance("kitten", "sitting", 2) is None
    assert is_within_edit_distance("flaw", "lawn", 2) == 2
    assert is_within_edit_distance("flaw", "lawn", 1) is None

    # Test longer strings
    assert is_within_edit_distance("abcdefg", "axcdexg", 2) == 2
    assert is_within_edit_distance("abcdefg", "axcdexgz", 3) == 3
    assert is_within_edit_distance("abcdefg", "axcdexgz", 2) is None

    # Test with non-adjacent insertions/deletions
    assert is_within_edit_distance("abcdef", "axcydef", 2) == 2
    assert is_within_edit_distance("abcdef", "axcydez", 3) == 3
    assert is_within_edit_distance("abcdef", "axcydez", 2) is None

    # Test unicode strings
    assert is_within_edit_distance("hello", "héllo", 1) == 1
    assert is_within_edit_distance("hello", "héllo", 0) is None

    # Test case sensitivity
    assert is_within_edit_distance("hello", "Hello", 1) == 1
    assert is_within_edit_distance("hello", "Hello", 0) is None

    print("All tests passed!")


if __name__ == "__main__":
    test_is_within_edit_distance()
