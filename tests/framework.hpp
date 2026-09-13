// Fault Containment Fabric — test framework.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Every case has a stable name and can be run on its own with --case <name>.
// Progress is printed and flushed immediately so a blocked case is never opaque.
// There is no timeout mechanism anywhere in this framework: a hanging case is a
// defect to diagnose, not something to terminate.

#ifndef FCF_TESTS_FRAMEWORK_HPP
#define FCF_TESTS_FRAMEWORK_HPP

#include <exception>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace fcf::test {

class Failure : public std::exception {
public:
    explicit Failure(std::string message) : message_(std::move(message)) {}
    [[nodiscard]] const char* what() const noexcept override { return message_.c_str(); }
    [[nodiscard]] const std::string& message() const noexcept { return message_; }

private:
    std::string message_;
};

struct Case {
    std::string suite;
    std::string name;
    std::function<void()> body;
};

class Registry {
public:
    static Registry& instance() {
        static Registry registry;
        return registry;
    }

    void add(std::string suite, std::string name, std::function<void()> body) {
        cases_.push_back(Case{std::move(suite), std::move(name), std::move(body)});
    }

    [[nodiscard]] const std::vector<Case>& cases() const noexcept { return cases_; }

private:
    std::vector<Case> cases_;
};

struct Registrar {
    Registrar(const char* suite, const char* name, std::function<void()> body) {
        Registry::instance().add(suite, name, std::move(body));
    }
};

/// Prints one phase transition and flushes immediately.
inline void emit(const std::string& phase) {
    std::cout << "  " << phase << std::endl;
}

template <class T>
[[nodiscard]] std::string debug_text(const T& value) {
    if constexpr (requires(std::ostringstream& stream, const T& v) { stream << v; }) {
        std::ostringstream stream;
        stream << value;
        return stream.str();
    } else if constexpr (requires(const T& v) { fcf::to_string(v); }) {
        auto text = fcf::to_string(value);
        return std::string(text);
    } else {
        return "<value>";
    }
}

[[noreturn]] inline void fail(const std::string& text) { throw Failure(text); }

inline void require(bool condition, const std::string& expression, const std::string& detail) {
    if (!condition) {
        throw Failure("requirement failed: " + expression + (detail.empty() ? "" : " -- " + detail));
    }
}

template <class A, class B>
void require_equal(const A& actual, const B& expected, const std::string& expression) {
    if (!(actual == expected)) {
        throw Failure("equality failed: " + expression + " -- actual " + debug_text(actual) +
                      " != expected " + debug_text(expected));
    }
}

template <class A, class B>
void require_not_equal(const A& actual, const B& unexpected, const std::string& expression) {
    if (actual == unexpected) {
        throw Failure("inequality failed: " + expression + " -- both sides are " +
                      debug_text(actual));
    }
}

/// Runs every registered case (or one selected case) and returns the failure count.
inline int run(int argc, char** argv) {
    std::string selected_case;
    std::string selected_suite;
    bool list_only = false;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--list") {
            list_only = true;
        } else if (argument == "--case" && i + 1 < argc) {
            selected_case = argv[++i];
        } else if (argument == "--suite" && i + 1 < argc) {
            selected_suite = argv[++i];
        }
    }

    const std::vector<Case>& cases = Registry::instance().cases();
    if (list_only) {
        for (const Case& entry : cases) {
            std::cout << entry.suite << "." << entry.name << "\n";
        }
        return 0;
    }

    std::size_t executed = 0;
    std::size_t failed = 0;
    for (const Case& entry : cases) {
        if (!selected_case.empty() && entry.name != selected_case) {
            continue;
        }
        if (!selected_suite.empty() && entry.suite != selected_suite) {
            continue;
        }
        ++executed;
        std::cout << "[" << entry.suite << "] CASE " << entry.name << " BEGIN" << std::endl;
        try {
            entry.body();
            std::cout << "[" << entry.suite << "] CASE " << entry.name << " PASS" << std::endl;
        } catch (const Failure& failure) {
            ++failed;
            std::cout << "[" << entry.suite << "] CASE " << entry.name << " FAIL: "
                      << failure.message() << std::endl;
        } catch (const std::exception& error) {
            ++failed;
            std::cout << "[" << entry.suite << "] CASE " << entry.name
                      << " FAIL (unexpected exception): " << error.what() << std::endl;
        } catch (...) {
            ++failed;
            std::cout << "[" << entry.suite << "] CASE " << entry.name
                      << " FAIL (unknown exception)" << std::endl;
        }
    }
    std::cout << "SUMMARY executed=" << executed << " failed=" << failed << std::endl;
    if (executed == 0) {
        std::cout << "SUMMARY no case matched the selection" << std::endl;
        return 2;
    }
    return failed == 0 ? 0 : 1;
}

}  // namespace fcf::test

#define FCF_TEST(suite_name, case_name)                                                  \
    static void suite_name##_##case_name##_body();                                       \
    static const ::fcf::test::Registrar suite_name##_##case_name##_registrar(            \
        #suite_name, #case_name, &suite_name##_##case_name##_body);                      \
    static void suite_name##_##case_name##_body()

#define FCF_REQUIRE(expression)     ::fcf::test::require((expression), #expression, std::string())

#define FCF_REQUIRE_MSG(expression, message)     ::fcf::test::require((expression), #expression, std::string(message))

#define FCF_EQ(actual, expected)     ::fcf::test::require_equal((actual), (expected), #actual " == " #expected)

#define FCF_NE(actual, unexpected)     ::fcf::test::require_not_equal((actual), (unexpected), #actual " != " #unexpected)

#define FCF_FAIL(message) ::fcf::test::fail(std::string(message))

#endif  // FCF_TESTS_FRAMEWORK_HPP
