package parser

func ReadHTTPFromFile(raw, host string) (*Request, error) {
	request, err := Parse(raw, host, true)
	if err != nil {
		return nil, err
	}
	return request, nil
}
