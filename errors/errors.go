package errors

// E 是内置的 error 类型，用于错误常量
type E string

// Error 实现 error 接口
func (e E) Error() string {
	return string(e)
}
