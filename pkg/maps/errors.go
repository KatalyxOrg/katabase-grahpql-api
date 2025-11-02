package maps

type NoEnoughParamsError struct{}

func (m *NoEnoughParamsError) Error() string {
	return "not enough parameters"
}
