#pragma once

#include <functional>
#include <type_traits>


template<typename... Ts> struct MakeVoid { typedef void type; };
template<typename... Ts> using DeduceVoid = typename MakeVoid<Ts...>::type;

template<bool Condition, typename T = void>
using EnableIf = typename std::enable_if<Condition, T>::type;

template<typename T = void>
using Decay = typename std::decay<T>::type;

template<typename T = void>
using AddPointer = typename std::add_pointer<T>::type;

template<typename T = void, typename V = void>
using IsSame = typename std::is_same<T, Decay<V>>::value;


template<typename T, typename = void>
struct IsCallable : std::is_function<T> { };

template<typename T>
struct IsCallable<T, typename std::enable_if<
	std::is_same<decltype(void(&T::operator())), void>::value
>::type> : std::true_type { };

template <typename T, typename = void>
struct IsIterable : std::false_type {};
template <typename T>
struct IsIterable<T, DeduceVoid<decltype(std::declval<T>().begin()),
	decltype(std::declval<T>().end())>>
	: std::true_type {};

template <typename T>
using IsFloatingPoint = std::is_floating_point<T>;

template <typename T>
using IsIntegral = std::is_integral<T>;