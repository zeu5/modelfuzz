package modelfuzz

func copyTrace(t *List[*Choice], filter func(*Choice) bool) *List[*Choice] {
	newL := NewList[*Choice]()
	for _, e := range t.Iter() {
		if filter(e) {
			newL.Append(e.Copy())
		}
	}
	return newL
}

func defaultCopyFilter() func(*Choice) bool {
	return func(sc *Choice) bool {
		return true
	}
}
