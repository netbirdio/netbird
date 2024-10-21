package refcounter

import "encoding/json"

// Ref holds the reference count and associated data for a key.
type Ref[O any] struct {
	Count int
	Out   O
}

// MarshalJSON implements the json.Marshaler interface for Ref.
func (r *Ref[O]) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Count int `json:"count"`
		Out   O   `json:"out"`
	}{
		Count: r.Count,
		Out:   r.Out,
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface for Ref.
func (r *Ref[O]) UnmarshalJSON(data []byte) error {
	var temp struct {
		Count int `json:"count"`
		Out   O   `json:"out"`
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	r.Count = temp.Count
	r.Out = temp.Out
	return nil
}
