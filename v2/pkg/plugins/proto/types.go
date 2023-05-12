//go:generate protoc --go-plugin_out=. --go-plugin_opt=paths=source_relative plugins.proto
package proto

import "errors"

var (
	ErrInvalidNumberOfArguments = errors.New("invalid number of arguments")
	ErrInvalidArgumentType      = errors.New("invalid argument type")
	ErrBlankArguments           = errors.New("blank arguments")
	ErrInvalidFunctionName      = errors.New("invalid function name")
)

func ToAnyScalarValue(value *AnyScalar) interface{} {
	switch value.Kind.(type) {
	case *AnyScalar_StringValue:
		return value.GetStringValue()
	case *AnyScalar_IntValue:
		return int(value.GetIntValue())
	case *AnyScalar_BoolValue:
		return value.GetBoolValue()
	case *AnyScalar_DoubleValue:
		return value.GetDoubleValue()
	default:
		return nil
	}
}

func ToAnyScalarFromInterface(val interface{}) *AnyScalar {
	scalar := &AnyScalar{}
	scalar.Kind = getScalarKindFromInterface(val)
	return scalar
}

func ToAnyScalarArray(arguments []interface{}) []*AnyScalar {
	result := make([]*AnyScalar, 0, len(arguments))
	for _, arg := range arguments {
		arg := arg
		scalar := &AnyScalar{}
		scalar.Kind = getScalarKindFromInterface(arg)
		result = append(result, scalar)
	}
	return result
}

func getScalarKindFromInterface(val interface{}) isAnyScalar_Kind {
	switch v := val.(type) {
	case string:
		return &AnyScalar_StringValue{v}
	case int:
		return &AnyScalar_IntValue{int64(v)}
	case bool:
		return &AnyScalar_BoolValue{v}
	case float64:
		return &AnyScalar_DoubleValue{v}
	default:
		return nil
	}
}
