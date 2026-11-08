"""C++ virtual calls: vtable slots read from the binary, method names read at the call site."""

import shutil
import subprocess

import pytest

from xray import codemap
from xray.cppvirtual import method_name, methods_at
from xray.disasm import disasm_result, parse_calls

TABLE = [(0x1000, 0x40, "caller"), (0x1100, 0x40, "tail"), (0x1200, 0x40, "other")]


@pytest.mark.parametrize("readable, name", [
    ("Shape::area() const", "area"),
    ("non-virtual thunk to ns::Shape::draw(_cairo*) const", "draw"),
    (("std::_Sp_counted_ptr_inplace<std::__detail::_NFA<std::__cxx11::regex_traits<char> >, std::allocator<void>, "
      "(__gnu_cxx::_Lock_policy)2>::_M_dispose()"), "_M_dispose"),
    ("Circle::~Circle()", "~Circle"),
    ("Handler<int>::on(int) [clone .lto_priv.0]", "on"),
])
def test_method_names(readable, name):
    assert method_name(readable) == name


def test_names_called_on_a_line():
    assert methods_at("    return shape->area() * scale.factor(2);") >= {"area", "factor"}
    assert methods_at('    calcSize();  // then redraw()') >= {"calcSize"}
    assert "redraw" not in methods_at('    calcSize();  // then redraw()')
    assert "open" not in methods_at('    log("open(file) failed");')


SLOTS = (
        "0000000000001000 <caller>:",
        "    1000:\tmov    (%rdi),%rax",
        "    1003:\tcall   *0x18(%rax)",          # slot 3
        "    1006:\tcall   *-0x40(%rbp)",         # a function pointer on the stack
        "    1009:\tmov    (%rbx),%rdx",
        "    100c:\tmov    0x10(%rdx),%rdx",      # slot 2 into a register
        "    1010:\tcmp    %rcx,%rdx",            # compared, not overwritten
        "    1013:\tcall   *%rdx",
        "    1015:\tcall   *%rsi",                # nothing known about rsi
        "",
        "0000000000001100 <tail>:",
        "    1100:\tmov    (%rdi),%rax",
        "    1103:\tjmp    *0x20(%rax)",          # slot 4, at the end of a function
        "",
        "0000000000001200 <other>:",
        "    1200:\tmov    0x10(%rdx),%rdx",      # rdx's vtable was in another function
        "    1204:\tcall   *%rdx",
)


def test_slot_calls_through_memory_registers_and_tail_jumps():
    result = parse_calls("\n".join(SLOTS), TABLE)

    assert result.slot_calls == (
        ("caller", 0x1003, 3), ("caller", 0x1013, 2), ("tail", 0x1103, 4),
    )
    assert result.indirect == 5


CLOBBERED = (
        "0000000000001000 <caller>:",
        "    1000:\tmov    (%rdi),%rax",
        "    1003:\tmov    0x8(%rax),%rax",
        "    1007:\tmov    (%rdi),%rbx",
        "    100a:\tmov    0x10(%rbx),%rbx",
        "    100e:\tcall   1200 <other>",
        "    1013:\tcall   *%rax",                # rax was clobbered by the call
        "    1015:\tcall   *%rbx",                # rbx is kept across calls
)


def test_a_call_ends_what_caller_saved_registers_hold():
    assert parse_calls("\n".join(CLOBBERED), TABLE).slot_calls == (("caller", 0x1015, 2),)


SHAPES = r"""#include <cstdio>
#include <cstdlib>

struct Shape {
    virtual ~Shape() {}
    virtual double area() const = 0;
    virtual const char *label() const { return "shape"; }
};

struct Circle : Shape {
    double r;
    explicit Circle(double r) : r(r) {}
    double area() const override { return 3.14159 * r * r; }
    const char *label() const override { return "circle"; }
};

struct Square : Shape {
    double s;
    explicit Square(double s) : s(s) {}
    double area() const override { return s * s; }
};

__attribute__((noinline)) double measure(const Shape *shape) {
    return shape->area();
}

__attribute__((noinline)) void show(const Shape *shape) {
    std::printf("%s\n", shape->label());
}

__attribute__((noinline)) void discard(Shape *shape) {
    delete shape;
}

int main(int argc, char **argv) {
    Shape *shape = argc > 1 ? static_cast<Shape *>(new Circle(std::atof(argv[1])))
                            : static_cast<Shape *>(new Square(2));
    std::printf("%f\n", measure(shape));
    show(shape);
    discard(shape);
    return 0;
}
"""


@pytest.mark.skipif(not all(shutil.which(t) for t in ("c++", "addr2line", "c++filt", "readelf", "objdump")),
                    reason="needs a C++ compiler and binutils")
@pytest.mark.parametrize("level", ["-O1", "-O2"])
def test_virtual_calls_of_a_local_program(tmp_path, level):
    source = tmp_path / "shapes.cpp"
    source.write_text(SHAPES)
    binary = tmp_path / "shapes"
    subprocess.run(["c++", "-g", level, "-o", str(binary), str(source)], check=True)
    codemap._CACHE.clear()

    lines = codemap.elf_callgraph(binary, "measure")
    text = "\n".join(lines)
    assert "⇢ Circle::area  (shapes.cpp:13)" in text
    assert "⇢ Square::area  (shapes.cpp:20)" in text
    assert "label" not in text   # same object, another slot
    assert "inferred" in text

    text = "\n".join(codemap.elf_callgraph(binary, "show"))
    assert "⇢ Circle::label  (shapes.cpp:14)" in text and "⇢ Shape::label  (shapes.cpp:7)" in text
    assert "Square" not in text   # Square keeps Shape::label

    back = "\n".join(codemap.elf_callgraph(binary, "Circle::area"))
    assert "called by (0, + 1 virtual):" in back and "⇠ measure  (shapes.cpp:2" in back

    gone = "\n".join(codemap.elf_callgraph(binary, "discard"))
    assert "1 virtual destructor calls (delete)" in gone and "⇢" not in gone

    whole = "\n".join(codemap.elf_callgraph(binary))
    assert "⇢ Circle::area" in whole and "Virtual calls made:" in whole


@pytest.mark.skipif(not all(shutil.which(t) for t in ("cc", "addr2line", "readelf", "objdump")),
                    reason="needs cc and binutils")
def test_c_function_pointers_are_not_called_virtual(tmp_path):
    source = tmp_path / "table.c"
    source.write_text(
        "#include <stdio.h>\n"
        "struct ops { int (*area)(int); int (*label)(int); };\n"
        "static int twice(int x) { return 2 * x; }\n"
        "static int area(int x) { return x * x; }\n"
        "__attribute__((noinline)) int run(const struct ops *o, int x) { return o->area(x); }\n"
        "int main(int argc, char **argv) {\n"
        "    static const struct ops table = { area, twice };\n"
        "    printf(\"%d\\n\", run(&table, argc));\n"
        "    return 0;\n"
        "}\n"
    )
    binary = tmp_path / "table"
    subprocess.run(["cc", "-g", "-O1", "-o", str(binary), str(source)], check=True)
    codemap._CACHE.clear()

    found = disasm_result(binary)
    text = "\n".join(codemap.elf_callgraph(binary, "run"))
    assert found.slot_calls   # it looks like a slot call ...
    assert "⇢" not in text and "Virtual calls" not in text   # ... but there are no vtables
