#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <cstdlib>
#include <set>
#include <cmath>
#include <thread>    // For std::thread
#include <cstring>   // For memcpy, memset
#include <vector>    // For std::vector (for raw memory in unique_ptr)
#include <memory>    // For std::unique_ptr
#include <cstdint>   // For uintptr_t for printing pointers
#include <fstream>   // For file I/O
#include <algorithm> // For std::find

#if __cplusplus <= 201103L
namespace std
{
template <typename T, typename... Args>
std::unique_ptr<T> male_unique(Args &&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
} // namespace std
#endif
// Forward declaration of exec for recursive calls (in functions)
void exec(std::string w, bool is_in_block = false);

struct LexValue; // Forward declaration

typedef std::vector<LexValue> LexArray;

struct LexValue
{
    enum Type
    {
        INT,
        FLOAT,
        STRING,
        ARRAY,
        BOOL,
        NONE,
        POINTER // type(represent a memory address)
    } type;

    int int_val;
    double float_val;
    std::string str_val;
    LexArray arr_val;
    bool bool_val;
    void *ptr_val;

    LexValue() : type(NONE), int_val(0), float_val(0.0), bool_val(false), ptr_val(nullptr) {}
    LexValue(int v) : type(INT), int_val(v), float_val(static_cast<double>(v)), bool_val(v != 0), ptr_val(nullptr) {}
    LexValue(double v) : type(FLOAT), int_val(static_cast<int>(v)), float_val(v), bool_val(v != 0.0), ptr_val(nullptr) {}
    LexValue(const std::string &v) : type(STRING), int_val(0), float_val(0.0), str_val(v), bool_val(!v.empty()), ptr_val(nullptr) {}
    LexValue(const LexArray &v) : type(ARRAY), int_val(0), float_val(0.0), arr_val(v), bool_val(!v.empty()), ptr_val(nullptr) {}
    LexValue(bool v) : type(BOOL), int_val(v ? 1 : 0), float_val(v ? 1.0 : 0.0), bool_val(v), ptr_val(nullptr) {}
    LexValue(void *p) : type(POINTER), int_val(0), float_val(0.0), bool_val(false), ptr_val(p) {} // Constructor for(ptr)

    void print() const
    {
        switch (type)
        {
        case INT:
            std::cout << int_val;
            break;
        case FLOAT:
            std::cout << float_val;
            break;
        case STRING:
            std::cout << str_val;
            break;
        case ARRAY:
        {
            std::cout << "[";
            for (size_t i = 0; i < arr_val.size(); ++i)
            {
                arr_val[i].print();
                if (i + 1 < arr_val.size())
                    std::cout << ", ";
            }
            std::cout << "]";
            break;
        }
        case BOOL:
            std::cout << (bool_val ? "true" : "false");
            break;
        case NONE:
            std::cout << "none";
            break;
        case POINTER:
            // Print memory address in hexadecimal format
            std::cout << "0x" << std::hex << reinterpret_cast<uintptr_t>(ptr_val) << std::dec;
            break;
        }
    }

    // Function to get the type name as a string
    std::string get_type_name() const
    {
        switch (type)
        {
        case INT:
            return "INT";
        case FLOAT:
            return "FLOAT";
        case STRING:
            return "STRING";
        case ARRAY:
            return "ARRAY";
        case BOOL:
            return "BOOL";
        case NONE:
            return "NONE";
        case POINTER:
            return "POINTER";
        }
        return "UNKNOWN";
    }

    bool equals(const LexValue &other) const
    {
        if (type != other.type)
            return false;
        switch (type)
        {
        case INT:
            return int_val == other.int_val;
        case FLOAT:
            return std::abs(float_val - other.float_val) < 1e-9; // Use tolerance for float comparison
        case STRING:
            return str_val == other.str_val;
        case BOOL:
            return bool_val == other.bool_val;
        case ARRAY:
            if (arr_val.size() != other.arr_val.size())
                return false;
            for (size_t i = 0; i < arr_val.size(); ++i)
                if (!arr_val[i].equals(other.arr_val[i]))
                    return false;
            return true;
        case POINTER:
            return ptr_val == other.ptr_val; // Compare(pointer addresses)
        case NONE:
            return true;
        }
        return false;
    }

    // Boolean representation of (value)
    bool as_bool() const
    {
        switch (type)
        {
        case BOOL:
            return bool_val;
        case INT:
            return int_val != 0;
        case FLOAT:
            return float_val != 0.0;
        case STRING:
            return !str_val.empty();
        case ARRAY:
            return !arr_val.empty();
        case POINTER:
            return ptr_val != nullptr;
        case NONE:
            return false;
        }
        return false;
    }
};

struct ReturnSignal
{
    LexValue return_value;
    explicit ReturnSignal(LexValue val) noexcept
        : return_value(std::move(val)) {}
};

std::map<std::string, LexValue> vars;
std::map<std::string, std::map<std::string, LexValue>> classes;
std::map<std::string, std::vector<std::string>> funcs;
std::map<std::string, std::vector<std::string>> funcs_with_braces;
std::map<std::string, std::vector<std::string>> init_funcs; //map for async functions
std::set<std::string> included_libs;
// JIT compiled code storage
std::map<std::string, std::vector<std::string>> jit_compiled_code;
// constraints
std::map<std::string, std::unique_ptr<unsigned char[]>> allocated_memory_blocks;
std::map<std::string, std::thread> active_threads;
LexValue thread_arg_global;
std::string current_class_context = "";
// Global state for new features
bool jit_mode_enabled = false;
LexValue last_return_value;

// AoT-compiler:start threogh namespace of course and a virtual machine.

namespace aot
{
// VM instruction code.
enum OpCode
{
    OP_RETURN,
    OP_CONSTANT,
    OP_ADD,
    OP_SUBTRACT,
    OP_MULTIPLY,
    OP_DIVIDE,
    OP_POP,
    OP_PRINT,
    OP_SET_GLOBAL,
    OP_GET_GLOBAL,
};

// A 'block(chunk)' of bytecode, which represents a compild program.
struct Chunk
{
    std::vector<uint8_t> code;
    std::vector<LexValue> constants;
};

// storage of compiled programs through a map.
std::map<std::string, Chunk> compiled_programs;

// bytecode disassembly
void disassemble_chunk(const Chunk &chunk, const std::string &name)
{
    std::cout << "--- Disassembly: " << name << " ---\n";
    for (size_t offset = 0; offset < chunk.code.size();)
    {
        printf("%04lu ", offset);
        uint8_t instruction = chunk.code[offset];
        switch (instruction)
        {
        case OP_RETURN:
            std::cout << "OP_RETURN\n";
            offset += 1;
            break;
        case OP_POP:
            std::cout << "OP_POP\n";
            offset += 1;
            break;
        case OP_PRINT:
            std::cout << "OP_PRINT\n";
            offset += 1;
            break;
        case OP_ADD:
            std::cout << "OP_ADD\n";
            offset += 1;
            break;
        case OP_SUBTRACT:
            std::cout << "OP_SUBTRACT\n";
            offset += 1;
            break;
        case OP_MULTIPLY:
            std::cout << "OP_MULTIPLY\n";
            offset += 1;
            break;
        case OP_DIVIDE:
            std::cout << "OP_DIVIDE\n";
            offset += 1;
            break;
        case OP_CONSTANT:
        {
            uint8_t const_index = chunk.code[offset + 1];
            std::cout << "OP_CONSTANT " << (int)const_index << " (";
            chunk.constants[const_index].print();
            std::cout << ")\n";
            offset += 2;
            break;
        }
        case OP_SET_GLOBAL:
        {
            uint8_t const_index = chunk.code[offset + 1];
            std::cout << "OP_SET_GLOBAL " << (int)const_index << " ('" << chunk.constants[const_index].str_val << "')\n";
            offset += 2;
            break;
        }
        case OP_GET_GLOBAL:
        {
            uint8_t const_index = chunk.code[offset + 1];
            std::cout << "OP_GET_GLOBAL " << (int)const_index << " ('" << chunk.constants[const_index].str_val << "')\n";
            offset += 2;
            break;
        }
        default:
            std::cout << "Unknown opcode: " << (int)instruction << "\n";
            offset += 1;
            break;
        }
    }
    std::cout << "---------------------------\n";
}

// Thee Virtual Machine
class VM
{
  public:
    VM() : ip(NULL) {}

    bool run(const Chunk &chunk)
    {
        ip = &chunk.code[0];
        stack.clear();

        for (;;)
        {
            uint8_t instruction = *ip++;
            switch (instruction)
            {
            case OP_RETURN:
            {
                return true; // Success
            }
            case OP_POP:
            {
                stack.pop_back();
                break;
            }
            case OP_PRINT:
            {
                stack.back().print();
                std::cout << std::endl;
                stack.pop_back();
                break;
            }
            case OP_CONSTANT:
            {
                uint8_t const_index = *ip++;
                stack.push_back(chunk.constants[const_index]);
                break;
            }
            case OP_GET_GLOBAL:
            {
                uint8_t name_index = *ip++;
                std::string var_name = chunk.constants[name_index].str_val;
                if (vars.find(var_name) == vars.end())
                {
                    std::cerr << "VM Runtime Error: Undefined variable '" << var_name << "'.\n";
                    return false;
                }
                stack.push_back(vars[var_name]);
                break;
            }
            case OP_SET_GLOBAL:
            {
                uint8_t name_index = *ip++;
                std::string var_name = chunk.constants[name_index].str_val;
                vars[var_name] = stack.back();
                // Note: set global does not pop the value, allowing `lex a = b = 5`
                break;
            }
            case OP_ADD:
            case OP_SUBTRACT:
            case OP_MULTIPLY:
            case OP_DIVIDE:
            {
                if (stack.size() < 2)
                {
                    std::cerr << "VM Runtime Error: Not enough operands for binary operation.\n";
                    return false;
                }
                LexValue b = stack.back();
                stack.pop_back();
                LexValue a = stack.back();
                stack.pop_back();

                if (a.type != LexValue::INT && a.type != LexValue::FLOAT)
                {
                    std::cerr << "VM Runtime Error: Left operand must be a number.\n";
                    return false;
                }
                if (b.type != LexValue::INT && b.type != LexValue::FLOAT)
                {
                    std::cerr << "VM Runtime Error: Right operand must be a number.\n";
                    return false;
                }

                double left = (a.type == LexValue::INT) ? a.int_val : a.float_val;
                double right = (b.type == LexValue::INT) ? b.int_val : b.float_val;
                double result_val;

                if (instruction == OP_ADD)
                    result_val = left + right;
                else if (instruction == OP_SUBTRACT)
                    result_val = left - right;
                else if (instruction == OP_MULTIPLY)
                    result_val = left * right;
                else if (instruction == OP_DIVIDE)
                {
                    if (right == 0.0)
                    {
                        std::cerr << "VM Runtime Error: Division by zero.\n";
                        return false;
                    }
                    result_val = left / right;
                }
                else
                {
                    // Should not happen or else......
                    return false;
                }

                // Preserve the INT type
                if (result_val == floor(result_val) && a.type == LexValue::INT && b.type == LexValue::INT)
                {
                    stack.push_back(LexValue(static_cast<int>(result_val)));
                }
                else
                {
                    stack.push_back(LexValue(result_val));
                }
                break;
            }
            default:
                std::cerr << "VM Error: Unknown opcode " << (int)instruction << std::endl;
                return false; // Filure
            }
        }
    }

  private:
    const uint8_t *ip;
    std::vector<LexValue> stack;
};

VM global_vm; // reusable VM instance.

// actual AOT Compiler
class Compiler
{
  public:
    bool compile(const std::string &program_name, const std::vector<std::string> &source_lines, Chunk &chunk)
    {
        this->chunk = &chunk;
        chunk.code.clear();
        chunk.constants.clear();

        for (const std::string &line : source_lines)
        {
            if (!compile_line(line))
            {
                std::cerr << "AOT Compile Error on program '" << program_name << "'.\n";
                return false;
            }
        }

        // Finish with a return statement
        emit_byte(OP_RETURN);
        return true;
    }

  private:
    Chunk *chunk;

    uint8_t make_constant(const LexValue &value)
    {
        chunk->constants.push_back(value);
        if (chunk->constants.size() > 255)
        {
            std::cerr << "Compile Error: Too many constants in one chunk.\n";
            return 0; // A'ght?
        }
        return (uint8_t)(chunk->constants.size() - 1);
    }

    void emit_byte(uint8_t byte)
    {
        chunk->code.push_back(byte);
    }

    void emit_bytes(uint8_t byte1, uint8_t byte2)
    {
        emit_byte(byte1);
        emit_byte(byte2);
    }

    bool compile_line(const std::string &line)
    {
        std::istringstream stream(line);
        std::string command;
        stream >> command;

        if (command == "lex")
        {
            std::string var_name, eq, val_str;
            stream >> var_name >> eq;
            std::getline(stream, val_str);
            val_str.erase(0, val_str.find_first_not_of(" \t\r\n")); // bools just make sense.
            val_str.erase(val_str.find_last_not_of(" \t\r\n") + 1);

            int i_val;
            double d_val;
            if (val_str.front() == '\'' && val_str.back() == '\'')
            {
                emit_bytes(OP_CONSTANT, make_constant(LexValue(val_str.substr(1, val_str.length() - 2))));
            }
            else if (sscanf(val_str.c_str(), "%lf", &d_val) == 1 && val_str.find('.') != std::string::npos)
            {
                emit_bytes(OP_CONSTANT, make_constant(LexValue(d_val)));
            }
            else if (sscanf(val_str.c_str(), "%d", &i_val) == 1)
            {
                emit_bytes(OP_CONSTANT, make_constant(LexValue(i_val)));
            }
            else // Assume it's a variable of course.
            {
                emit_bytes(OP_GET_GLOBAL, make_constant(LexValue(val_str)));
            }
            // GOD, thankyou!
            emit_bytes(OP_SET_GLOBAL, make_constant(LexValue(var_name)));
            emit_byte(OP_POP); // Pop the val left on the stack by 'set'
        }
        else if (command == "std::out")
        {
            std::string var_name;
            stream >> var_name;
            emit_bytes(OP_GET_GLOBAL, make_constant(LexValue(var_name)));
            emit_byte(OP_PRINT);
        }
        return true;
    }
};

} // namespace aot

// aot compiletr: done

static std::string trim(const std::string &s)
{
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos)
        return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// hex(octal) parser
bool parseInt(const std::string &s, int &out)
{
    char *endptr;
    long val = std::strtol(s.c_str(), &endptr, 0);
    if (*endptr == '\0')
    {
        out = static_cast<int>(val);
        return true;
    }
    return false;
}
// scientific notation
bool parseDouble(const std::string &s, double &out)
{
    char *endptr;
    double val = std::strtod(s.c_str(), &endptr);
    if (*endptr == '\0')
    {
        out = val;
        return true;
    }
    return false;
}

// arrays
static std::vector<std::string> parseArrayElements(const std::string &arr_content)
{
    std::vector<std::string> elems;
    std::string token;
    bool in_quotes = false;
    int bracket_level = 0; // To handle nested arrays

    for (size_t i = 0; i < arr_content.size(); ++i)
    {
        char c = arr_content[i];
        if (c == '\'')
        {
            in_quotes = !in_quotes;
            token += c; // Keep quotes in token for parseValue to handle
        }
        else if (c == '[' && !in_quotes)
        { // Handle nested arrays
            bracket_level++;
            token += c;
        }
        else if (c == ']' && !in_quotes)
        {
            bracket_level--;
            token += c;
        }
        else if (c == ',' && !in_quotes && bracket_level == 0) // Only split if not inside quotes or nested array
        {
            elems.push_back(trim(token));
            token.clear();
        }
        else
        {
            token += c;
        }
    }
    if (!token.empty())
        elems.push_back(trim(token));
    return elems;
}

LexValue eval_expression(const std::string &expr_str); // Forward declare for use in parseValue

LexValue parseValue(const std::string &val_str)
{
    std::string val = trim(val_str);
    if (val.empty())
        return LexValue();

    if (val == "true")
        return LexValue(true);
    if (val == "false")
        return LexValue(false);

    if (val.size() >= 2 && val.front() == '\'' && val.back() == '\'')
    {
        return LexValue(val.substr(1, val.size() - 2));
    }
    // Handle array literals directly here if they aren't parsed by assignment implicitly of courde
    if (val.size() >= 2 && val.front() == '[' && val.back() == ']')
    {
        std::string arr_content = val.substr(1, val.size() - 2);
        LexArray arr;
        std::vector<std::string> elems = parseArrayElements(arr_content);
        for (const auto &elem_str : elems)
        {
            arr.push_back(parseValue(elem_str));
        }
        return LexValue(arr);
    }

    size_t l_bracket = val.find('[');
    size_t r_bracket = val.find(']');
    if (l_bracket != std::string::npos && r_bracket != std::string::npos && r_bracket > l_bracket)
    {
        std::string array_name = trim(val.substr(0, l_bracket));
        std::string index_str = trim(val.substr(l_bracket + 1, r_bracket - l_bracket - 1));
        if (vars.count(array_name) && vars[array_name].type == LexValue::ARRAY)
        {
            LexValue index_val = eval_expression(index_str);
            if (index_val.type == LexValue::INT)
            {
                int idx = index_val.int_val;
                if (idx >= 0 && static_cast<size_t>(idx) < vars[array_name].arr_val.size())
                {
                    return vars[array_name].arr_val[idx];
                }
                else
                {
                    std::cerr << "Runtime error: Index " << idx << " out of bounds for array '" << array_name << "'\n";
                    return LexValue();
                }
            }
        }
    }

    int ival;
    if (parseInt(val, ival))
        return LexValue(ival);

    double dval;
    if (parseDouble(val, dval))
        return LexValue(dval);
    // variable refernce(&)
    if (vars.count(val))
    {
        return vars[val];
    }
    return LexValue(val);
}

LexValue eval_expression(const std::string &expr_str)
{
    std::string expr = trim(expr_str);
    std::istringstream ss(expr);
    std::string lhs_str, op_str, rhs_str;
    ss >> lhs_str >> op_str;
    if (op_str.empty())
    { // just a single value
        return parseValue(lhs_str);
    }
    std::getline(ss, rhs_str); // get rest of line as rhs since the lhs has a'eady beeing used, a'ght?

    LexValue lhs = parseValue(lhs_str);
    LexValue rhs = eval_expression(rhs_str); // recursive call for(chained ops)

    if ((lhs.type != LexValue::INT && lhs.type != LexValue::FLOAT) ||
        (rhs.type != LexValue::INT && rhs.type != LexValue::FLOAT))
    {
        // fall_back for (non-numeric types || complex expressions)
        return parseValue(expr_str);
    }

    double l = (lhs.type == LexValue::INT) ? lhs.int_val : lhs.float_val;
    double r = (rhs.type == LexValue::INT) ? rhs.int_val : rhs.float_val;

    double result;
    if (op_str == "+")
        result = l + r;
    else if (op_str == "-")
        result = l - r;
    else if (op_str == "*")
        result = l * r;
    else if (op_str == "/")
        result = (r != 0) ? l / r : 0;
    else if (op_str == "%")
        result = fmod(l, r);
    else
        return parseValue(expr_str);
    if (result == floor(result) && lhs.type == LexValue::INT && rhs.type == LexValue::INT)
    {
        return LexValue(static_cast<int>(result));
    }
    return LexValue(result);
}

// Ternary: cond ? expr1 : expr2
LexValue evalTernary(const std::string &expr)
{
    size_t qmark = expr.find('?');
    size_t colon = expr.rfind(':');
    if (qmark == std::string::npos || colon == std::string::npos || qmark > colon)
    {
        std::cerr << "Ternary error: Malformed ternary expression: " << expr << std::endl;
        return LexValue();
    }

    std::string cond_str = trim(expr.substr(0, qmark));
    std::string true_expr = trim(expr.substr(qmark + 1, colon - qmark - 1));
    std::string false_expr = trim(expr.substr(colon + 1));

    LexValue cond_val = parseValue(cond_str);

    return cond_val.as_bool() ? parseValue(true_expr) : parseValue(false_expr);
}

// Split(std::log) into namespace and function parts
void splitNamespaceFunction(const std::string &cmd, std::string &ns, std::string &func)
{
    size_t pos = cmd.find("::");
    if (pos != std::string::npos)
    {
        ns = cmd.substr(0, pos);
        func = cmd.substr(pos + 2);
    }
    else
    {
        ns = "";
        func = cmd;
    }
}

// rpn(postfix)(evaluation)
LexValue evalRPN(const std::vector<std::string> &tokens)
{
    std::vector<LexValue> stack;
    for (const std::string &tok : tokens)
    {
        if (tok == "+" || tok == "-" || tok == "*" || tok == "/")
        {
            if (stack.size() < 2)
            {
                std::cerr << "RPN error: too few operands for operator " << tok << "\n";
                return LexValue();
            }
            LexValue b = stack.back();
            stack.pop_back();
            LexValue a = stack.back();
            stack.pop_back();
            if ((a.type == LexValue::INT || a.type == LexValue::FLOAT) &&
                (b.type == LexValue::INT || b.type == LexValue::FLOAT))
            {
                double left = (a.type == LexValue::INT) ? a.int_val : a.float_val;
                double right = (b.type == LexValue::INT) ? b.int_val : b.float_val;
                double res = 0;
                if (tok == "+")
                    res = left + right;
                else if (tok == "-")
                    res = left - right;
                else if (tok == "/")
                {
                    if (right == 0)
                    {
                        std::cerr << "RPN error: division by zero (returns none)\n";
                        return LexValue();
                    }
                    res = left / right;
                }
                // Determinant(int or float)
                if (res == floor(res))
                    stack.push_back(LexValue(static_cast<int>(res)));
                else
                    stack.push_back(LexValue(res));
            }
            else
            {
                std::cerr << "RPN error: operands for " << tok << " must be numeric\n";
                return LexValue();
            }
        }
        else
        {
            // push literal onto stack
            if (vars.count(tok))
            {
                stack.push_back(vars[tok]);
            }
            else
            {
                stack.push_back(parseValue(tok));
            }
        }
    }
    if (stack.size() != 1)
    {
        std::cerr << "RPN error: leftover items on stack\n";
        return LexValue();
    }
    return stack[0];
}
//func(exec)_dif thread using std::thread
void executeFloatscriptFunctionThreaded(std::string func_name, LexValue arg_val)
{
    if (funcs_with_braces.count(func_name))
    {
        thread_arg_global = arg_val;

        // for(line:function){exec()}
        for (const std::string &line : funcs_with_braces[func_name])
        {
            exec(line);
        }
        thread_arg_global = LexValue(); // reset thread
    }
    else
    {
        std::cerr << "[Thread Error] Function '" << func_name << "' not found for threaded execution.\n";
    }
}

// 'init' async function exec in thread, faded...
void executeInitFunctionThreaded(std::string func_name)
{
    if (init_funcs.count(func_name))
    {
        // for(line:function){exec()}
        for (const std::string &line : init_funcs[func_name])
        {
            exec(line);
        }
    }
    else
    {
        std::cerr << "[Thread Error] Async function '" << func_name << "' not found for threaded execution.\n";
    }
}

bool eval_condition(const std::string &cond_str)
{
    std::string cond = trim(cond_str);
    std::string lhs_str, op_str, rhs_str;

    size_t semi_pos = cond.find(';');
    if (semi_pos != std::string::npos)
    { // if _i ; v_
        op_str = ";";
        lhs_str = trim(cond.substr(0, semi_pos));
        rhs_str = trim(cond.substr(semi_pos + 1));
    }
    else
    {
        std::istringstream ss(cond);
        ss >> lhs_str >> op_str >> rhs_str;
    }

    if (op_str.empty())
    { // if _my_bool_
        return parseValue(lhs_str).as_bool();
    }

    LexValue lhs = parseValue(lhs_str);
    LexValue rhs = parseValue(rhs_str);

    if (op_str == ";")
    { // "in array" check
        if (rhs.type != LexValue::ARRAY)
            return false;
        for (const auto &elem : rhs.arr_val)
        {
            if (elem.equals(lhs))
                return true;
        }
        return false;
    }

    return eval_expression(cond).as_bool();
}

std::vector<std::string> read_code_block()
{
    std::vector<std::string> block;
    std::string line_str;
    int brace_level = 1;
    while (brace_level > 0 && std::getline(std::cin, line_str))
    {
        if (trim(line_str).find('{') != std::string::npos)
            brace_level++;
        if (trim(line_str).find('}') != std::string::npos)
            brace_level--;

        if (brace_level > 0)
        {
            block.push_back(line_str);
        }
    }
    return block;
}

void execute_code_block(const std::vector<std::string> &block)
{
    for (const auto &line : block)
    {
        exec(line, true);
    }
}

void exec(std::string w, bool is_in_block)
{
    //comments: if (a line starts with '//', ignore it.
    std::string trimmed_w = trim(w);
    if (trimmed_w.rfind("//", 0) == 0)
    {
        return;
    }

    std::istringstream line(w);
    std::string full_cmd, arg;
    line >> full_cmd;

    if (full_cmd.rfind("println_", 0) == 0)
    {
        std::string target = full_cmd.substr(8);
        if (target.front() == '\'' && target.back() == '\'')
        {
            std::cout << target.substr(1, target.length() - 2) << std::endl;
        }
        else
        {
            parseValue(target).print();
            std::cout << std::endl;
        }
        return;
    }
    if (full_cmd == ".rt")
    {
        std::string next_part;
        line >> next_part;
        if (next_part == "{")
        {
            auto block = read_code_block();
            if (!block.empty())
            {
                throw ReturnSignal(eval_expression(block[0]));
            }
        }
        return;
    }
    if (full_cmd == "auto")
    {
        std::string jit_arg;
        line >> jit_arg;
        if (jit_arg == "<jit>")
        {
            jit_mode_enabled = true;
            std::cout << "[JIT auto-compilation enabled for subsequent blocks]\n";
        }
        return;
    }
    if (full_cmd == "while")
    {
        std::string remainder;
        std::getline(line, remainder);
        size_t start_pos = remainder.find('_');
        size_t end_pos = remainder.rfind('_');
        size_t brace_pos = remainder.rfind('{');
        if (start_pos != std::string::npos && end_pos != std::string::npos && start_pos < end_pos)
        {
            std::string cond_str = remainder.substr(start_pos + 1, end_pos - start_pos - 1);
            std::vector<std::string> block;
            if (brace_pos != std::string::npos)
            {
                block = read_code_block();
            }
            while (eval_condition(cond_str))
            {
                execute_code_block(block);
            }
        }
        else
        {
            std::cerr << "Syntax error: while _condition_ { ... }\n";
        }
        return;
    }

    if (full_cmd == "./help")
    {
        std::cout << "\n--- Floatscript Help (`./help`) ---\n\n"
                  << "** General Commands:\n"
                  << "  exit                      - Exits the interpreter.\n"
                  << "  ./help                    - Displays this help message.\n"
                  << "  // <comment>              - A single-line comment.\n\n"
                  << "** Variables & Assignment:\n"
                  << "  lex <var> = <val>         - Assigns any type (string, int, float, bool, array, expression).\n"
                  << "                              e.g., lex my_str = 'hello'\n"
                  << "                              e.g., lex g = d + c\n"
                  << "  let <var> = <int>         - Assigns an integer value.\n"
                  << "  float <var> = <flt>       - Assigns a floating-point value.\n"
                  << "  lex <var> = <c> ? <a> : <b> - Ternary assignment based on condition <c>.\n\n"
                  << "** Output:\n"
                  << "  std::out <var/val>        - Prints a variable or literal value.\n"
                  << "  std::out (i:v)            - Prints array 'v' excluding element at index 'i'.\n"
                  << "  println_<var>             - Alternative way to print a variable.\n"
                  << "  println_'literal'         - Alternative way to print a literal string.\n"
                  << "  std::log <msg>            - Prints a message with a [STD LOG] prefix.\n\n"
                  << "** Control Flow & Blocks:\n"
                  << "  if _<cond>_ { ... }         - Conditional execution. e.g., if _i > 5_ { ... }\n"
                  << "  if _<val> ; <arr>_ { ... }  - Checks if 'val' is in 'arr'.\n"
                  << "  while _<cond>_ { ... }      - Loop while a condition is true.\n"
                  << "  for _<v> : <array>_ { ... } - Range-based for loop.\n"
                  << "  .rt { <expr> }            - Returns a value from a block or function.\n\n"
                  << "** Functions:\n"
                  << "  def <name>                - Defines a multi-line function (ends with 'end').\n"
                  << "  fn <name> { ... }         - Defines a multi-line function (ends with '}').\n"
                  << "  init <name> { ... }       - Defines a special asynchronous function that runs in the background when called.\n"
                  << "  <name>                    - Calls the function.\n\n"
                  << "** JIT Compilation:\n"
                  << "  auto <jit>                - Enables simulated JIT for subsequent blocks.\n"
                  << "  jit::compile <r> { ... }  - Manually compiles a routine.\n"
                  << "  jit::run <r>              - Executes a compiled routine.\n\n"
                  << "** AOT Compilation (New):\n"
                  << "  aot::compile <p> { ... }  - Compiles a program into bytecode.\n"
                  << "  aot::run <p>              - Runs a compiled program in the VM.\n"
                  << "  aot::dis <p>              - Disassembles a compiled program's bytecode.\n\n"
                  << "** Libraries (`#include <lib1, lib2, ...>`):\n\n"
                  << "  <rpn>, <fs>, <mem>, <vect>, <jit>, <io>, <bit>\n"
                  << "-------------------------------------\n\n";
        return;
    }

    // work with(#include <library>)
    if (w.find("#include") == 0)
    {
        size_t start = w.find('<'), end = w.find('>');
        if (start != std::string::npos && end != std::string::npos && end > start)
        {
            std::string libs_str = w.substr(start + 1, end - start - 1);
            std::istringstream libs_stream(libs_str);
            std::string lib;
            while (std::getline(libs_stream, lib, ','))
            {
                included_libs.insert(trim(lib));
                std::cout << "Included library: <" << trim(lib) << ">\n";
            }
        }
        else
        {
            std::cerr << "Malformed include statement.\n";
        }
        return;
    }

    std::string ns, cmd;
    splitNamespaceFunction(full_cmd, ns, cmd);
    //compilre comnds
    if (ns == "aot")
    {
        if (cmd == "compile")
        {
            std::string program_name, brace;
            line >> program_name >> brace;
            if (brace != "{")
            {
                std::cerr << "aot::compile error: Expected '{' after program name. Found: '" << brace << "'\n";
                return;
            }
            if (aot::compiled_programs.count(program_name))
            {
                std::cerr << "aot::compile error: Program '" << program_name << "' is already compiled. \n";
                return;
            }
            std::vector<std::string> source_lines = read_code_block();
            aot::Chunk new_chunk;
            aot::Compiler compiler;
            if (compiler.compile(program_name, source_lines, new_chunk))
            {
                aot::compiled_programs[program_name] = new_chunk;
                std::cout << "AOT compilation successful for program '" << program_name << "'.\n";
            }
            else
            {
                std::cerr << "AOT compilation failed for program '" << program_name << "'.\n";
            }
            return;
        }
        if (cmd == "run")
        {
            std::string program_name;
            line >> program_name;
            if (!aot::compiled_programs.count(program_name))
            {
                std::cerr << "aot::run error: Program '" << program_name << "' not found.\n";
                return;
            }
            std::cout << "--- Executing AOT program: " << program_name << " ---\n";
            aot::global_vm.run(aot::compiled_programs[program_name]);
            std::cout << "--- Finished AOT program: " << program_name << " ---\n";
            return;
        }
        if (cmd == "dis")
        { // disassemble
            std::string program_name;
            line >> program_name;
            if (!aot::compiled_programs.count(program_name))
            {
                std::cerr << "aot::disassemble error: Program '" << program_name << "' not found.\n";
                return;
            }
            aot::disassemble_chunk(aot::compiled_programs[program_name], program_name);
            return;
        }
        std::cerr << "Unknown aot:: command: " << cmd << std::endl;
        return;
    }

    // standard namespace library (std::) commands
    if (ns == "std")
    {
        if (cmd == "log")
        {
            std::string msg;
            std::getline(line, msg);
            std::cout << "[STD LOG] " << trim(msg) << std::endl;
            return;
        }
        if (cmd == "out")
        {
            std::string out;
            std::getline(line, out);
            out = trim(out);

            // (i:v)
            if (out.front() == '(' && out.back() == ')')
            {
                std::string inner = trim(out.substr(1, out.length() - 2));
                size_t colon_pos = inner.find(':');
                if (colon_pos != std::string::npos)
                {
                    std::string idx_var_name = trim(inner.substr(0, colon_pos));
                    std::string arr_var_name = trim(inner.substr(colon_pos + 1));
                    LexValue idx_val = parseValue(idx_var_name);
                    LexValue arr_val = parseValue(arr_var_name);
                    if (arr_val.type == LexValue::ARRAY && idx_val.type == LexValue::INT)
                    {
                        int exclude_idx = idx_val.int_val;
                        for (int i = 0; i < (int)arr_val.arr_val.size(); ++i)
                        {
                            if (i != exclude_idx)
                            {
                                arr_val.arr_val[i].print();
                                std::cout << " ";
                            }
                        }
                        std::cout << std::endl;
                    }
                    else
                    {
                        std::cerr << "std::out error: Expected (index:array) format with valid types.\n";
                    }
                    return; // Return after all that
                }
            }

            size_t l = out.find('[');
            size_t r = out.find(']');
            if (l != std::string::npos && r != std::string::npos && r > l)
            {
                std::string name = out.substr(0, l);
                int idx = 0;
                if (!parseInt(out.substr(l + 1, r - l - 1), idx))
                {
                    std::cerr << "Invalid index: " << out.substr(l + 1, r - l - 1) << "\n";
                    return;
                }
                if (vars.count(name) && vars[name].type == LexValue::ARRAY)
                {
                    if (idx >= 0 && idx < static_cast<int>(vars[name].arr_val.size()))
                    {
                        vars[name].arr_val[idx].print();
                        std::cout << std::endl;
                    }
                    else
                    {
                        std::cerr << "Index out of bounds for array '" << name << "': " << idx << "\n";
                    }
                }
                else
                {
                    std::cerr << "Variable '" << name << "' not found or not an array.\n";
                }
            }
            else
            {
                if (vars.count(out))
                {
                    vars[out].print();
                    std::cout << std::endl;
                }
                else
                {
                    // if it's not a variable, treat as a direct literal(string)
                    parseValue(out).print();
                    std::cout << std::endl;
                }
            }
            return;
        }
        //Rpn librayr
        if (cmd == "rpn")
        {
            if (included_libs.count("rpn") == 0)
            {
                std::cerr << "Error: <rpn> library not included. Use #include <rpn>\n";
                return;
            }
            std::string possible_var;
            std::istream::sentry s(line);          // restore stream
            std::streampos old_pos = line.tellg(); // save stream position

            if (line >> possible_var)
            { // read rpn(tok)
                std::string eq;
                if (line >> eq && eq == "=")
                { // if/not assigned
                    std::vector<std::string> tokens;
                    std::string tok;
                    while (line >> tok)
                        tokens.push_back(tok);
                    LexValue res = evalRPN(tokens);
                    if (res.type != LexValue::NONE)
                    {
                        vars[possible_var] = res;
                        res.print();
                        std::cout << std::endl;
                    }
                    return;
                }
                else
                {
                    line.clear();        // clear(error_flags)
                    line.seekg(old_pos); // default to start
                    std::vector<std::string> tokens;
                    std::string tok;
                    while (line >> tok)
                        tokens.push_back(tok);
                    LexValue res = evalRPN(tokens);
                    if (res.type != LexValue::NONE)
                    {
                        res.print();
                        std::cout << std::endl;
                    }
                    return;
                }
            }
            std::cerr << "Usage: std::rpn [var =] <rpn-expr>\n";
            return;
        }
        std::cerr << "Unknown std:: command: " << cmd << std::endl;
        return;
    }
    //end(standard(lib_commands))

    // JIT library
    if (ns == "jit")
    {
        if (included_libs.count("jit") == 0)
        {
            std::cerr << "Error: <jit> library not included. Use #include <jit>\n";
            return;
        }
        if (cmd == "compile")
        { // jit::compile routine_name { ... }
            std::string routine_name, brace;
            line >> routine_name >> brace;
            if (brace != "{")
            {
                std::cerr << "jit::compile error: Expected '{' after routine name. Found: '" << brace << "'\n";
                return;
            }
            if (jit_compiled_code.count(routine_name))
            {
                std::cerr << "jit::compile error: Routine '" << routine_name << "' is already compiled.\n";
                return;
            }
            jit_compiled_code[routine_name] = std::vector<std::string>();
            std::string line_str;
            std::cout << "Compiling routine '" << routine_name << "' (type '}' to finish):\n";
            while (std::getline(std::cin, line_str) && trim(line_str) != "}")
            {
                if (!line_str.empty())
                    jit_compiled_code[routine_name].push_back(line_str);
            }
            std::cout << "Routine '" << routine_name << "' compiled.\n";
            return;
        }
        if (cmd == "run")
        { // jit::run routine_name
            std::string routine_name;
            line >> routine_name;
            if (!jit_compiled_code.count(routine_name))
            {
                std::cerr << "jit::run error: Routine '" << routine_name << "' not found.\n";
                return;
            }
            for (const std::string &routine_line : jit_compiled_code[routine_name])
            {
                exec(routine_line);
            }
            return;
        }
        if (cmd == "free")
        { // jit::free routine_name
            std::string routine_name;
            line >> routine_name;
            if (jit_compiled_code.count(routine_name))
            {
                jit_compiled_code.erase(routine_name);
                std::cout << "Freed compiled routine '" << routine_name << "'.\n";
            }
            else
            {
                std::cerr << "jit::free error: Routine '" << routine_name << "' not found.\n";
            }
            return;
        }
        std::cerr << "Unknown jit:: command: " << cmd << std::endl;
        return;
    }

    // Vector lib. dynamic array manipulation
    if (ns == "vect")
    {
        if (included_libs.count("vect") == 0)
        {
            std::cerr << "Error: <vect> library not included. Use #include <vect>\n";
            return;
        }
        if (cmd == "push")
        { // vect::push vec_name value
            std::string vec_name, val_str;
            line >> vec_name;
            std::getline(line, val_str);
            if (!vars.count(vec_name) || vars[vec_name].type != LexValue::ARRAY)
            {
                std::cerr << "vect::push error: '" << vec_name << "' is not a valid vector.\n";
                return;
            }
            vars[vec_name].arr_val.push_back(parseValue(trim(val_str)));
            return;
        }
        if (cmd == "pop")
        { // vect::pop vec_name [result_var]
            std::string vec_name, result_var;
            line >> vec_name >> result_var;
            if (!vars.count(vec_name) || vars[vec_name].type != LexValue::ARRAY)
            {
                std::cerr << "vect::pop error: '" << vec_name << "' is not a valid vector.\n";
                return;
            }
            if (vars[vec_name].arr_val.empty())
            {
                std::cerr << "vect::pop error: Cannot pop from an empty vector '" << vec_name << "'.\n";
                return;
            }
            LexValue popped_val = vars[vec_name].arr_val.back();
            vars[vec_name].arr_val.pop_back();
            if (!result_var.empty())
            {
                vars[result_var] = popped_val;
            }
            return;
        }
        if (cmd == "size")
        { // vect::size result_var = vec_name
            std::string result_var, eq, vec_name;
            line >> result_var >> eq >> vec_name;
            if (eq != "=")
            {
                std::cerr << "vect::size error: Invalid syntax. Use 'vect::size res = vec'.\n";
                return;
            }
            if (!vars.count(vec_name) || vars[vec_name].type != LexValue::ARRAY)
            {
                std::cerr << "vect::size error: '" << vec_name << "' is not a valid vector.\n";
                return;
            }
            vars[result_var] = LexValue(static_cast<int>(vars[vec_name].arr_val.size()));
            return;
        }
        if (cmd == "clear")
        { // vect::clear vec_name
            std::string vec_name;
            line >> vec_name;
            if (!vars.count(vec_name) || vars[vec_name].type != LexValue::ARRAY)
            {
                std::cerr << "vect::clear error: '" << vec_name << "' is not a valid vector.\n";
                return;
            }
            vars[vec_name].arr_val.clear();
            return;
        }
        std::cerr << "Unknown vect:: command: " << cmd << std::endl;
        return;
    }

    // low_level part
    if (ns == "mem")
    {
        if (included_libs.count("mem") == 0)
        {
            std::cerr << "Error: <mem> library not included. Use #include <mem>\n";
            return;
        }

        if (cmd == "alloc")
        { // mem::alloc var_name size_in_bytes
            std::string var_name;
            int size;
            line >> var_name >> size;
            if (size <= 0)
            {
                std::cerr << "mem::alloc error: Size must be positive.\n";
                return;
            }
            if (vars.count(var_name))
            {
                std::cerr << "mem::alloc error: Variable '" << var_name << "' already exists. Cannot re-allocate without freeing.\n";
                return;
            }
            try
            {
                // alloc(dynamic_mem) using unique_ptr
                std::unique_ptr<unsigned char[]> block(new unsigned char[size]);
                // store(unique_ptr in map), using the var_name as key
                allocated_memory_blocks[var_name] = std::move(block);
                // store(ptr)
                vars[var_name] = LexValue(allocated_memory_blocks[var_name].get());
                // alloc_mem_sizes[var_name] = size;
                std::cout << "Allocated " << size << " bytes at ";
                vars[var_name].print(); //so far so good<lusungu>
                std::cout << " for '" << var_name << "'\n";
            }
            catch (const std::bad_alloc &e)
            {
                std::cerr << "mem::alloc error: Failed to allocate memory: " << e.what() << "\n";
            }
            return;
        }
        if (cmd == "free")
        { // mem::free var_name
            std::string var_name;
            line >> var_name;
            if (!vars.count(var_name) || vars[var_name].type != LexValue::POINTER)
            {
                std::cerr << "mem::free error: Variable '" << var_name << "' not a valid memory pointer (or not allocated by mem::alloc).\n";
                return;
            }
            if (allocated_memory_blocks.count(var_name))
            {
                allocated_memory_blocks.erase(var_name); // del(unique_ptr(call))
                vars.erase(var_name);                    // remove the ptr var from(scope)
                // remove size(if_stored)?
                std::cout << "Freed memory for '" << var_name << "'\n";
            }
            else
            {
                std::cerr << "mem::free error: Memory block for '" << var_name << "' not found or already freed.\n";
            }
            return;
        }
        if (cmd == "write_byte")
        { // mem::write_byte ptr_var offset value
            std::string ptr_var_name;
            int offset, value;
            line >> ptr_var_name >> offset >> value;
            if (!vars.count(ptr_var_name) || vars[ptr_var_name].type != LexValue::POINTER)
            {
                std::cerr << "mem::write_byte error: '" << ptr_var_name << "' is not a valid memory pointer.\n";
                return;
            }
            if (offset < 0)
            {
                std::cerr << "mem::write_byte error: Offset cannot be negative.\n";
                return;
            }
            if (value < 0 || value > 255)
            {
                std::cerr << "mem::write_byte error: Value must be between 0 and 255 (a byte).\n";
                return;
            }

            unsigned char *ptr = static_cast<unsigned char *>(vars[ptr_var_name].ptr_val);
            // writing past allocated memory will cause a crash.
            ptr[offset] = static_cast<unsigned char>(value);
            std::cout << "Wrote byte " << value << " to address 0x" << std::hex // new style
                      << reinterpret_cast<uintptr_t>(ptr + offset) << std::dec << "\n";
            return;
        }
        if (cmd == "read_byte")
        { // mem::read_byte result_var ptr_var offset
            std::string result_var_name, ptr_var_name;
            int offset;
            line >> result_var_name >> ptr_var_name >> offset;
            if (!vars.count(ptr_var_name) || vars[ptr_var_name].type != LexValue::POINTER)
            {
                std::cerr << "mem::read_byte error: '" << ptr_var_name << "' is not a valid memory pointer.\n";
                return;
            }
            if (offset < 0)
            {
                std::cerr << "mem::read_byte error: Offset cannot be negative.\n";
                return;
            }

            unsigned char *ptr = static_cast<unsigned char *>(vars[ptr_var_name].ptr_val);
            // dont read past alloc(mem)[warned]
            int byte_value = static_cast<int>(ptr[offset]);
            vars[result_var_name] = LexValue(byte_value);
            std::cout << "Read byte " << byte_value << " from address 0x" << std::hex
                      << reinterpret_cast<uintptr_t>(ptr + offset) << std::dec << " into '" << result_var_name << "'\n";
            return;
        }
        if (cmd == "spawn_thread")
        { // mem::spawn_thread thread_name function_name [arg_value_or_var]
            std::string thread_name, func_name;
            std::string arg_str_raw; // raw string(litera)
            line >> thread_name >> func_name;
            std::getline(line, arg_str_raw); // read(line)
            arg_str_raw = trim(arg_str_raw);

            if (active_threads.count(thread_name))
            {
                std::cerr << "mem::spawn_thread error: Thread '" << thread_name << "' already exists or is running. Use mem::join_thread first.\n";
                return;
            }
            if (!funcs_with_braces.count(func_name))
            {
                std::cerr << "mem::spawn_thread error: Function '" << func_name << "' not defined with braces (fn).\n";
                return;
            }

            LexValue arg_val; // Val to(pass to thread)
            if (!arg_str_raw.empty())
            {
                arg_val = parseValue(arg_str_raw); // Parse it as a value (could be literal or variable content)
            }
            else
            {
                arg_val = LexValue(); // void |no(argument)
            }
            // Launch the thread
            // std::thread(movement(obj))
            active_threads[thread_name] = std::thread(executeFloatscriptFunctionThreaded, func_name, arg_val);
            std::cout << "Spawned thread '" << thread_name << "' to execute function '" << func_name << "'.\n";
            return;
        }
        if (cmd == "join_thread")
        { // mem::join_thread thread_name
            std::string thread_name;
            line >> thread_name;
            if (active_threads.count(thread_name))
            {
                if (active_threads[thread_name].joinable())
                {
                    active_threads[thread_name].join(); // wait(thread_finish)
                    std::cout << "Joined thread '" << thread_name << "'.\n";
                }
                else
                {
                    std::cerr << "mem::join_thread error: Thread '" << thread_name << "' is not joinable (already joined or not started/valid).\n";
                }
                active_threads.erase(thread_name); //remove from(active list.after augmentation(joined)
            }
            else
            {
                std::cerr << "mem::join_thread error: Thread '" << thread_name << "' not found.\n";
            }
            return;
        }

        std::cerr << "Unknown mem:: command: " << cmd << std::endl;
        return;
    }
    // Filesystem/math namespace for advanced math
    if (ns == "fs")
    {
        if (included_libs.count("fs") == 0)
        {
            std::cerr << "Error: <fs> library not included. Use #include <fs>\n";
            return;
        }

        if (cmd == "dydx")
        {
            std::string result_var, eq, func_to_diff, at_word, val_str;
            line >> result_var >> eq >> func_to_diff >> at_word;
            std::getline(line, val_str);
            val_str = trim(val_str);

            if (eq != "=" || at_word != "at")
            {
                std::cerr << "fs::dydx error: Invalid syntax. Use 'fs::dydx result_var = <function> at <value>'\n";
                return;
            }

            LexValue input_val = parseValue(val_str);
            double x = 0.0;
            if (input_val.type == LexValue::INT)
            {
                x = static_cast<double>(input_val.int_val);
            }
            else if (input_val.type == LexValue::FLOAT)
            {
                x = input_val.float_val;
            }
            else
            {
                std::cerr << "fs::dydx error: Differentiation point must be numeric. Got: '" << val_str << "'\n";
                return;
            }

            const double h = 1e-7; // A small value for h for finite difference method
            double f_x, f_xh;

            if (func_to_diff == "sin")
            {
                f_x = std::sin(x);
                f_xh = std::sin(x + h);
            }
            else if (func_to_diff == "cos")
            {
                f_x = std::cos(x);
                f_xh = std::cos(x + h);
            }
            else if (func_to_diff == "tan")
            {
                f_x = std::tan(x);
                f_xh = std::tan(x + h);
            }
            else if (func_to_diff == "ln")
            {
                if (x <= 0)
                {
                    std::cerr << "fs::dydx(ln) error: Input must be positive.\n";
                    return;
                }
                f_x = std::log(x);
                f_xh = std::log(x + h);
            }
            else if (func_to_diff == "log")
            {
                if (x <= 0)
                {
                    std::cerr << "fs::dydx(log) error: Input must be positive.\n";
                    return;
                }
                f_x = std::log10(x);
                f_xh = std::log10(x + h);
            }
            else if (func_to_diff == "abs")
            {
                f_x = std::abs(x);
                f_xh = std::abs(x + h);
            }
            else
            {
                std::cerr << "fs::dydx error: Function '" << func_to_diff << "' is not supported for differentiation.\n";
                return;
            }

            double derivative = (f_xh - f_x) / h;
            vars[result_var] = LexValue(derivative);
            std::cout << "fs::dydx(" << func_to_diff << " at " << x << ") = " << derivative << " -> stored in '" << result_var << "'\n";
            return;
        }

        std::string result_var, eq, value_str;
        line >> result_var >> eq;
        std::getline(line, value_str);
        value_str = trim(value_str);

        if (eq != "=")
        {
            std::cerr << "fs:: error: Expected '=' for assignment. Usage: fs::<func> result_var = <value>\n";
            return;
        }

        LexValue input_val = parseValue(value_str);
        double num_val = 0.0;
        bool is_numeric = false;

        if (input_val.type == LexValue::INT)
        {
            num_val = static_cast<double>(input_val.int_val);
            is_numeric = true;
        }
        else if (input_val.type == LexValue::FLOAT)
        {
            num_val = input_val.float_val;
            is_numeric = true;
        }

        if (!is_numeric)
        {
            std::cerr << "fs:: error: Math functions require a numeric argument. Got: '" << value_str << "'\n";
            return;
        }

        double result = 0.0;
        if (cmd == "sin" || cmd == "cos" || cmd == "tan")
        {
            // For trig functions, you might want to treat input as radians
            if (cmd == "sin")
                result = std::sin(num_val);
            else if (cmd == "cos")
                result = std::cos(num_val);
            else if (cmd == "tan")
                result = std::tan(num_val);
        }
        else if (cmd == "ln")
        {
            if (num_val <= 0)
            {
                std::cerr << "fs::ln error: Input must be positive.\n";
                return;
            }
            result = std::log(num_val);
        }
        else if (cmd == "log")
        {
            if (num_val <= 0)
            {
                std::cerr << "fs::log error: Input must be positive.\n";
                return;
            }
            result = std::log10(num_val);
        }
        else if (cmd == "abs")
        {
            result = std::abs(num_val);
        }
        else
        {
            std::cerr << "Unknown fs:: command: " << cmd << std::endl;
            return;
        }

        vars[result_var] = LexValue(result);
        std::cout << "fs::" << cmd << "(" << num_val << ") = " << result << " -> stored in '" << result_var << "'\n";
        return;
    }

    // File I/O operations
    if (ns == "io")
    {
        if (included_libs.count("io") == 0)
        {
            std::cerr << "Error: <io> library not included. Use #include <io>\n";
            return;
        }

        if (cmd == "read")
        { // io::read result_var_name file_path
            std::string result_var_name, file_path;
            line >> result_var_name;
            std::getline(line, file_path);
            file_path = trim(file_path);

            if (file_path.empty())
            {
                std::cerr << "io::read error: Missing file path.\n";
                return;
            }

            std::ifstream infile(file_path);
            if (!infile.is_open())
            {
                std::cerr << "io::read error: Could not open file '" << file_path << "' for reading.\n";
                return;
            }

            std::stringstream buffer;
            buffer << infile.rdbuf();
            vars[result_var_name] = LexValue(buffer.str());
            std::cout << "Read content of '" << file_path << "' into '" << result_var_name << "'.\n";
            infile.close();
            return;
        }
        if (cmd == "write")
        { // io::write file_path value
            std::string file_path, value_str;
            line >> file_path;
            std::getline(line, value_str);
            value_str = trim(value_str);

            if (file_path.empty())
            {
                std::cerr << "io::write error: Missing file path.\n";
                return;
            }

            std::ofstream outfile(file_path);
            if (!outfile.is_open())
            {
                std::cerr << "io::write error: Could not open file '" << file_path << "' for writing.\n";
                return;
            }

            LexValue val_to_write = parseValue(value_str);
            switch (val_to_write.type)
            {
            case LexValue::INT:
                outfile << val_to_write.int_val;
                break;
            case LexValue::FLOAT:
                outfile << val_to_write.float_val;
                break;
            case LexValue::STRING:
                outfile << val_to_write.str_val;
                break;
            case LexValue::BOOL:
                outfile << (val_to_write.bool_val ? "true" : "false");
                break;
            case LexValue::NONE:
                outfile << "none";
                break;
            case LexValue::POINTER:
                outfile << "0x" << std::hex << reinterpret_cast<uintptr_t>(val_to_write.ptr_val) << std::dec;
                break;
            case LexValue::ARRAY:
            { // Print array elements
                outfile << "[";
                for (size_t i = 0; i < val_to_write.arr_val.size(); ++i)
                {
                    LexValue &elem = val_to_write.arr_val[i];
                    switch (elem.type)
                    {
                    case LexValue::INT:
                        outfile << elem.int_val;
                        break;
                    case LexValue::FLOAT:
                        outfile << elem.float_val;
                        break;
                    case LexValue::STRING:
                        outfile << elem.str_val;
                        break;
                    case LexValue::BOOL:
                        outfile << (elem.bool_val ? "true" : "false");
                        break;
                    case LexValue::NONE:
                        outfile << "none";
                        break;
                    case LexValue::POINTER:
                        outfile << "0x" << std::hex << reinterpret_cast<uintptr_t>(elem.ptr_val) << std::dec;
                        break;
                    case LexValue::ARRAY:
                        outfile << "[Nested Array]";
                        break; // Simplified for nested arrays
                    }
                    if (i + 1 < val_to_write.arr_val.size())
                        outfile << ", ";
                }
                outfile << "]";
                break;
            }
            }
            std::cout << "Wrote value to '" << file_path << "'.\n";
            outfile.close();
            return;
        }
        std::cerr << "Unknown io:: command: " << cmd << std::endl;
        return;
    }

    // Bitwise operations
    if (ns == "bit")
    {
        if (included_libs.count("bit") == 0)
        {
            std::cerr << "Error: <bit> library not included. Use #include <bit>\n";
            return;
        }

        std::string result_var, val1_str, val2_str;
        line >> result_var;

        if (cmd == "not")
        { // bit::not result_var val
            line >> val1_str;
            LexValue val = parseValue(val1_str);
            if (val.type != LexValue::INT)
            {
                std::cerr << "bit::not error: Operand must be an integer. Got: '" << val1_str << "'\n";
                return;
            }
            vars[result_var] = LexValue(~val.int_val);
            std::cout << "bit::not result stored in '" << result_var << "'.\n";
            return;
        }

        line >> val1_str >> val2_str; // For binary ops
        LexValue val1 = parseValue(val1_str);
        LexValue val2 = parseValue(val2_str);

        if (val1.type != LexValue::INT || val2.type != LexValue::INT)
        {
            std::cerr << "bit::" << cmd << " error: Both operands must be integers. Got: '"
                      << val1_str << "' and '" << val2_str << "'\n";
            return;
        }

        int res = 0;
        if (cmd == "and")
        {
            res = val1.int_val & val2.int_val;
        }
        else if (cmd == "or")
        {
            res = val1.int_val | val2.int_val;
        }
        else if (cmd == "xor")
        {
            res = val1.int_val ^ val2.int_val;
        }
        else if (cmd == "lshift")
        {
            res = val1.int_val << val2.int_val;
        }
        else if (cmd == "rshift")
        {
            res = val1.int_val >> val2.int_val;
        }
        else
        {
            std::cerr << "Unknown bit:: command: " << cmd << std::endl;
            return;
        }
        vars[result_var] = LexValue(res);
        std::cout << "bit::" << cmd << " result stored in '" << result_var << "'.\n";
        return;
    }

    // Type checking command
    if (full_cmd == "typecheck")
    {
        std::string var_name, expected_type_str;
        line >> var_name >> expected_type_str;

        if (!vars.count(var_name))
        {
            std::cerr << "typecheck error: Variable '" << var_name << "' not found.\n";
            return;
        }

        LexValue::Type expected_type;
        if (expected_type_str == "INT")
            expected_type = LexValue::INT;
        else if (expected_type_str == "FLOAT")
            expected_type = LexValue::FLOAT;
        else if (expected_type_str == "STRING")
            expected_type = LexValue::STRING;
        else if (expected_type_str == "ARRAY")
            expected_type = LexValue::ARRAY;
        else if (expected_type_str == "BOOL")
            expected_type = LexValue::BOOL;
        else if (expected_type_str == "NONE")
            expected_type = LexValue::NONE;
        else if (expected_type_str == "POINTER")
            expected_type = LexValue::POINTER;
        else
        {
            std::cerr << "typecheck error: Unknown type '" << expected_type_str << "'. Valid types: INT, FLOAT, STRING, ARRAY, BOOL, NONE, POINTER.\n";
            return;
        }

        if (vars[var_name].type == expected_type)
        {
            std::cout << "'" << var_name << "' is of type " << expected_type_str << ". (True)\n";
        }
        else
        {
            std::cout << "'" << var_name << "' is NOT of type " << expected_type_str << ". (False, actual type: " << vars[var_name].get_type_name() << ")\n";
        }
        return;
    }

    if (cmd == "let")
    {
        line >> arg;
        std::string eq, val_str;
        line >> eq;
        std::getline(line, val_str);
        val_str = trim(val_str);

        int ival;
        if (parseInt(val_str, ival))
        {
            vars[arg] = LexValue(ival);
        }
        else
        {
            std::cerr << "Error: 'let' can only assign integer values. Found: '" << val_str << "'\n";
        }
        return;
    }

    if (cmd == "float")
    {
        line >> arg;
        std::string eq, val_str;
        line >> eq;
        std::getline(line, val_str);
        val_str = trim(val_str);

        double dval;
        if (parseDouble(val_str, dval))
        {
            vars[arg] = LexValue(dval);
        }
        else
        {
            std::cerr << "Error: 'float' can only assign floating-point values. Found: '" << val_str << "'\n";
        }
        return;
    }

    if (cmd == "lex")
    {
        line >> arg; // var(name)
        std::string eq, rest;
        line >> eq;               // =(assign)
        std::getline(line, rest); // the rest of the line is the val(expr)
        rest = trim(rest);

        if (jit_mode_enabled)
        {
            std::cout << "[JIT compiling assignment for '" << arg << "']\n";
            // In a real JIT, we'd compile the expression here.
            // For now, it's a simulation.
        }

        if (!rest.empty() && rest.find('?') != std::string::npos && rest.find(':') != std::string::npos)
        {
            // ternary(assignment)
            vars[arg] = evalTernary(rest);
        }
        else
        {
            // Use eval_expression to handle arithmetic, vars, and literals
            vars[arg] = eval_expression(rest);
        }
        return;
    }

    if (cmd == "opt")
    {
        line >> arg;
        if (arg == "out")
        {
            std::string out;
            std::getline(line, out);
            out = trim(out);

            size_t l = out.find('[');
            size_t r = out.find(']');
            if (l != std::string::npos && r != std::string::npos && r > l)
            {
                std::string name = out.substr(0, l);
                int idx = 0;
                if (!parseInt(out.substr(l + 1, r - l - 1), idx))
                {
                    std::cerr << "Invalid index: " << out.substr(l + 1, r - l - 1) << "\n";
                    return;
                }
                if (vars.count(name) && vars[name].type == LexValue::ARRAY)
                {
                    if (idx >= 0 && idx < static_cast<int>(vars[name].arr_val.size()))
                    {
                        vars[name].arr_val[idx].print();
                        std::cout << std::endl;
                    }
                    else
                    {
                        std::cerr << "Index out of bounds for array '" << name << "': " << idx << "\n";
                    }
                }
                else
                {
                    std::cerr << "Variable '" << name << "' not found or not an array.\n";
                }
            }
            else
            {
                if (vars.count(out))
                {
                    vars[out].print();
                    std::cout << std::endl;
                }
                else
                {
                    // if(=!(var)) treat as literal string
                    std::cout << parseValue(out).str_val << std::endl;
                }
            }
            return;
        }
        std::cerr << "Unknown opt command: " << arg << std::endl;
        return;
    }

    if (cmd == "sys")
    {
        line >> arg;
        if (arg == "log")
        {
            std::string log_msg;
            std::getline(line, log_msg);
            std::cout << "[LOG] " << trim(log_msg) << std::endl;
            return;
        }
        std::cerr << "Unknown sys command: " << arg << std::endl;
        return;
    }

    if (cmd == "if")
    {
        std::string remainder;
        std::getline(line, remainder);
        remainder = trim(full_cmd + " " + remainder); // Reconstruct the line

        size_t start_pos = remainder.find('_');
        size_t end_pos = remainder.rfind('_');
        size_t brace_pos = remainder.rfind('{');

        if (start_pos != std::string::npos && end_pos != std::string::npos && start_pos < end_pos)
        {
            std::string cond_str = remainder.substr(start_pos + 1, end_pos - start_pos - 1);
            std::vector<std::string> block;
            if (brace_pos != std::string::npos)
            {
                block = read_code_block();
            }
            if (jit_mode_enabled)
            {
                std::cout << "[JIT compiling if block]\n";
            }
            if (eval_condition(cond_str))
            {
                execute_code_block(block);
            }
            return; //update...
        }

        std::string var_name, op, val_str, then_word;
        std::istringstream old_if_line(w); //full linw_w
        old_if_line >> cmd >> var_name >> op >> val_str >> then_word;

        if (then_word != "then")
        {
            std::cerr << "Syntax error: Expected 'then' after if condition. Found: '" << then_word << "'\n";
            return;
        }

        if (!vars.count(var_name))
        {
            std::cerr << "If error: Variable '" << var_name << "' not found.\n";
            return;
        }

        LexValue left_val = vars[var_name];       // var(val)
        LexValue right_val = parseValue(val_str); // comparison

        bool condition = false;

        // conditional(operator)
        if (op == "==")
        {
            condition = left_val.equals(right_val);
        }
        else if (op == "!=")
        {
            condition = !left_val.equals(right_val);
        }
        else if (op == "<")
        {
            if (left_val.type == LexValue::INT && right_val.type == LexValue::INT)
                condition = left_val.int_val < right_val.int_val;
            else if (left_val.type == LexValue::FLOAT && right_val.type == LexValue::FLOAT)
                condition = left_val.float_val < right_val.float_val;
            else
                std::cerr << "Comparison error: '<' requires numeric types. Got: " << left_val.get_type_name() << ", " << right_val.get_type_name() << "\n";
        }
        else if (op == ">")
        {
            if (left_val.type == LexValue::INT && right_val.type == LexValue::INT)
                condition = left_val.int_val > right_val.int_val;
            else if (left_val.type == LexValue::FLOAT && right_val.type == LexValue::FLOAT)
                condition = left_val.float_val > right_val.float_val;
            else
                std::cerr << "Comparison error: '>' requires numeric types. Got: " << left_val.get_type_name() << ", " << right_val.get_type_name() << "\n";
        }
        else
        {
            std::cerr << "If error: Unknown operator '" << op << "'.\n";
        }

        std::string rest_of_line;
        std::getline(old_if_line, rest_of_line);
        rest_of_line = trim(rest_of_line);

        // Check for 'else' keyword
        size_t else_pos = rest_of_line.find("else");
        std::string then_cmd_str;
        std::string else_cmd_str;

        if (else_pos != std::string::npos)
        { //once 'else' found
            then_cmd_str = trim(rest_of_line.substr(0, else_pos));
            else_cmd_str = trim(rest_of_line.substr(else_pos + 4)); // +4 for "else" length
        }
        else
        { // if No 'else' found
            then_cmd_str = rest_of_line;
        }

        // if(true)(exec)
        if (condition)
        {
            // stop execution of the current line.using return
            if (!then_cmd_str.empty() && then_cmd_str.find("return") != std::string::npos)
                return;
            if (!then_cmd_str.empty())
                exec(then_cmd_str); // possible(recursive(call))
        }
        else
        { // Execute else block if condition is false
            if (!else_cmd_str.empty() && else_cmd_str.find("return") != std::string::npos)
                return;
            if (!else_cmd_str.empty())
                exec(else_cmd_str);
        }
        return;
    }
    //range_based for loop, for x : arr { //code }
    if (cmd == "for")
    {
        std::string remainder;
        std::getline(line, remainder);
        remainder = trim(full_cmd + " " + remainder); // Reconstruct

        size_t start_pos = remainder.find('_');
        size_t end_pos = remainder.rfind('_');
        size_t brace_pos = remainder.rfind('{');

        if (start_pos != std::string::npos && end_pos != std::string::npos && start_pos < end_pos)
        {
            std::string inner_expr = remainder.substr(start_pos + 1, end_pos - start_pos - 1);
            size_t colon_pos = inner_expr.find(':');
            if (colon_pos != std::string::npos)
            {
                std::string loop_var = trim(inner_expr.substr(0, colon_pos));
                std::string arr_name = trim(inner_expr.substr(colon_pos + 1));
                LexValue arr_val = parseValue(arr_name);
                if (arr_val.type == LexValue::ARRAY)
                {
                    std::vector<std::string> block;
                    if (brace_pos != std::string::npos)
                    {
                        block = read_code_block();
                    }
                    if (jit_mode_enabled)
                    {
                        std::cout << "[JIT compiling for block]\n";
                    }
                    for (const auto &elem : arr_val.arr_val)
                    {
                        vars[loop_var] = elem;
                        execute_code_block(block);
                    }
                }
                else
                {
                    std::cerr << "For loop error: '" << arr_name << "' is not an array.\n";
                }
            }
            return;
        }

        std::istringstream old_for_line(w);
        std::string loop_var, separator, for_cmd_token;
        old_for_line >> for_cmd_token >> loop_var >> separator;

        if (separator == ":") // Range-based for loop
        {
            std::string container_var_str;
            old_for_line >> container_var_str;
            std::string rest_of_loop_body;
            std::getline(old_for_line, rest_of_loop_body);
            rest_of_loop_body = trim(rest_of_loop_body);

            LexValue container_val = parseValue(container_var_str); // Parse to get array from var or literal

            if (container_val.type != LexValue::ARRAY) // Use container_val directly
            {
                std::cerr << "For loop error: '" << container_var_str << "' is not an array.\n";
                return;
            }
            for (const auto &element : container_val.arr_val) // Iterate on container_val's array
            {
                vars[loop_var] = element;
                if (!rest_of_loop_body.empty())
                    exec(rest_of_loop_body);
            }
            return;
        }
        else if (separator == "from") //numerical one
        {
            std::string start_val_str, to_word, end_val_str;
            old_for_line >> start_val_str >> to_word >> end_val_str;

            if (to_word != "to")
            {
                std::cerr << "Syntax error: Expected 'to' in for loop. Found: '" << to_word << "'\n";
                return;
            }

            LexValue start_lex_val = parseValue(start_val_str);
            LexValue end_lex_val = parseValue(end_val_str);

            if (start_lex_val.type != LexValue::INT || end_lex_val.type != LexValue::INT)
            {
                std::cerr << "For loop error: 'from' and 'to' values must be integers.\n";
                return;
            }

            int start_val = start_lex_val.int_val;
            int end_val = end_lex_val.int_val;

            // repition(iteration)
            std::string rest_of_loop_body;
            std::getline(old_for_line, rest_of_loop_body);
            rest_of_loop_body = trim(rest_of_loop_body);

            for (int i = start_val; i <= end_val; ++i)
            {
                vars[loop_var] = LexValue(i); // Update loop(var)
                if (!rest_of_loop_body.empty())
                    exec(rest_of_loop_body); // for each iteration {exec}
            }
            return;
        }
        else
        { // Unrecognized for loop syntax
            std::cerr << "For loop error: Invalid syntax. Use 'for var : array' or 'for var from start to end'.\n";
            return;
        }
    }

    if (cmd == "class")
    {
        line >> arg; // class name
        if (classes.count(arg))
        {
            std::cerr << "Class '" << arg << "' already defined.\n";
            return;
        }
        classes[arg] = std::map<std::string, LexValue>(); // initialize(map)(for.empty
        std::cout << "Class '" << arg << "' defined.\n";
        return;
    }

    if (cmd == "with")
    {
        std::string class_name, brace;
        line >> class_name >> brace;

        if (brace != "{")
        {
            std::cerr << "Syntax error: Expected '{' after class name in 'with' statement. Found: '" << brace << "'\n";
            return;
        }

        if (!classes.count(class_name))
        {
            std::cerr << "With error: Class '" << class_name << "' not found.\n";
            return;
        }

        std::string previous_context = current_class_context;
        current_class_context = class_name;

        std::string line_str;
        std::cout << "Entering context of class '" << class_name << "' (type '}' to exit):\n";
        while (std::getline(std::cin, line_str) && trim(line_str) != "}")
        {
            if (!line_str.empty())
                exec(line_str);
        }

        current_class_context = previous_context;
        std::cout << "Exited context of class '" << class_name << "'.\n";
        return;
    }

    if (cmd == "this")
    {
        if (current_class_context.empty())
        {
            std::cerr << "Error: 'this' can only be used within a 'with' block.\n";
        }
        else
        {
            std::cout << current_class_context << std::endl;
        }
        return;
    }

    if (cmd == "lhs" || cmd == "rhs")
    {
        std::string eq, val_str;
        line >> eq >> val_str;
        val_str = trim(val_str);
        if (eq == "=")
        {
            vars[cmd] = parseValue(val_str);
        }
        else
        {
            std::cerr << "Syntax error: Expected '=' to assign to '" << cmd << "'.\n";
        }
        return;
    }

    if (cmd == "set")
    {
        std::string class_or_member, member_name, eq_token;
        line >> class_or_member >> member_name >> eq_token;

        std::string val_str;
        std::getline(line, val_str);
        val_str = trim(val_str);

        std::string target_class = current_class_context;
        std::string target_member = class_or_member;

        if (!current_class_context.empty())
        {
            // set member = value
            target_member = class_or_member;
            eq_token = member_name;
            std::stringstream ss;
            ss << eq_token << " " << val_str;
            val_str = trim(ss.str());
        }
        else
        {
            // Outside a 'with' block set class member = value
            target_class = class_or_member;
            target_member = member_name;
        }

        if (!classes.count(target_class))
        {
            std::cerr << "Class '" << target_class << "' not found for set operation.\n";
            return;
        }
        if (eq_token != "=")
        {
            std::cerr << "Syntax error: Expected '=' in set operation. Found: '" << eq_token << "'\n";
            return;
        }

        LexValue val = parseValue(val_str);
        classes[target_class][target_member] = val;
        std::cout << "Set member '" << target_member << "' in class '" << target_class << "'.\n";
        return;
    }
    if (cmd == "get")
    {
        std::string class_or_member, member_name;
        line >> class_or_member;
        line >> member_name;

        std::string target_class = current_class_context;
        std::string target_member = class_or_member;

        if (current_class_context.empty())
        {
            // Definitely.
            target_class = class_or_member;
            target_member = member_name;
        }

        if (classes.count(target_class) && classes[target_class].count(target_member))
        {
            classes[target_class][target_member].print();
            std::cout << std::endl;
        }
        else
        {
            std::cerr << "Class '" << target_class << "' or member '" << target_member << "' not found for get operation.\n";
        }
        return;
    }

    if (cmd == "def") // function definition
    {
        line >> arg; // name
        if (funcs.count(arg) || funcs_with_braces.count(arg))
        {
            std::cerr << "Function '" << arg << "' already defined.\n";
            return;
        }
        funcs[arg] = std::vector<std::string>();
        std::string line_str;
        std::cout << "Enter function body (type 'end' to finish):\n";
        while (std::getline(std::cin, line_str) && trim(line_str) != "end")
        {
            funcs[arg].push_back(line_str);
        }
        std::cout << "Function '" << arg << "' defined.\n";
        return;
    }

    if (cmd == "fn") // fn definition with'{}'
    {
        line >> arg; //name
        std::string brace;
        line >> brace; // read(open.brace)

        if (brace != "{")
        {
            std::cerr << "Syntax error: Expected '{' after function name in 'fn' definition. Found: '" << brace << "'\n";
            return;
        }
        if (funcs.count(arg) || funcs_with_braces.count(arg))
        {
            std::cerr << "Function '" << arg << "' already defined.\n";
            return;
        }

        funcs_with_braces[arg] = read_code_block();
        std::cout << "Function '" << arg << "' defined.\n";
        return;
    }

    if (cmd == "init") // definitely...
    {
        line >> arg; // function name
        std::string brace;
        line >> brace;

        if (brace != "{")
        {
            std::cerr << "Syntax error: Expected '{' after async function name in 'init' definition. Found: '" << brace << "'\n";
            return;
        }
        if (funcs.count(arg) || funcs_with_braces.count(arg) || init_funcs.count(arg))
        {
            std::cerr << "Function '" << arg << "' already defined.\n";
            return;
        }

        init_funcs[arg] = read_code_block();
        std::cout << "Async function '" << arg << "' defined. Call it by name to run in the background.\n";
        return;
    }

    // if(command matches->defined function name) attempt to call
    if (funcs.count(full_cmd))
    {
        for (const std::string &func_line : funcs[full_cmd])
        {
            exec(func_line); // exec(each.line(fn{}))
        }
        return;
    }

    if (funcs_with_braces.count(full_cmd))
    {
        try
        {
            for (const std::string &func_line : funcs_with_braces[full_cmd])
            {
                exec(func_line); // "
            }
        }
        catch (const ReturnSignal &sig)
        {
            last_return_value = sig.return_value;
            std::cout << "Function '" << full_cmd << "' returned: ";
            last_return_value.print();
            std::cout << std::endl;
        }
        return;
    }

    if (init_funcs.count(full_cmd))
    {
        std::string thread_name = full_cmd;
        if (active_threads.count(thread_name))
        {
            std::cerr << "Error: An async function or thread with the name '" << thread_name << "' is already running.\n";
            return;
        }
        // Launch the thread
        active_threads[thread_name] = std::thread(executeInitFunctionThreaded, full_cmd);
        std::cout << "Started async function '" << full_cmd << "' in the background.\n";
        return;
    }

    if (cmd == "thread_arg")
    {
        if (thread_arg_global.type != LexValue::NONE)
        {
            thread_arg_global.print();
            std::cout << std::endl;
        }
        else
        {
            std::cout << "none (thread_arg not set or consumed)\n";
        }
        return;
    }

    // if(no_cmd(matches){unknown}
    std::cerr << "Unknown command: " << full_cmd << std::endl;
}

//Whew!, at least
int main()
{
    std::string code;
    std::cout << "This is |floatscript.flt| made by: L.Luh4n4 (type 'exit' to terminate):\n";
    std::cout << "Type '#include <lib_name>' to include libraries (<rpn>, <mem>, <fs>, <vect>, <jit>, <io>, <bit>).\n";
    std::cout << "Type './help' for a list of commands.\n";

    while (std::getline(std::cin, code) && trim(code) != "exit")
    {
        // wrapped exec()
        try
        {
            exec(code);
        }
        catch (const ReturnSignal &sig)
        {
            last_return_value = sig.return_value;
            std::cout << "Script returned: ";
            last_return_value.print();
            std::cout << std::endl;
        }
    }
    //carefull
    for (auto &pair : active_threads)
    { //for each pair in active thread
        if (pair.second.joinable())
        {
            std::cerr << "Warning: Unjoined thread '" << pair.first << "' detected at exit. Joining now...\n";
            pair.second.join(); // ensure(thread_completion)
        }
    }
    // ptr in alloc(mem) -> auto(free mem when mao is destroyed(at(end(main))))
    return 0;
} //please_coMPILE
  // L�


#include <string>

extern "C" {

const char* run_script(const char* code) {
    static std::string output;

    // Call your real FloatScript engine here
    output = FloatScript::execute(std::string(code));

    return output.c_str();
}

}
