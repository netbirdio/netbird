//go:build !darwin || ios

package systemops

// refreshUnderlay has nothing to do here: these platforms resolve the
// physical path per connection or route NetBird's own traffic by fwmark.
func (r *SysOps) refreshUnderlay(bool) error {
	return nil
}
