"""Runtime narrowing of a declared base type to the concrete model a plugin expects."""


def expect[T](value: object, cls: type[T]) -> T:
    if not isinstance(value, cls):
        raise TypeError(f"expected {cls.__name__}")
    return value
