package netbird

# all rules for peer connectivity and firewall
all[rule] {
  rule := array.concat(
    rules_from_groups(["all"], "dst", "accept", ""),
    rules_from_groups(["all"], "src", "accept", ""))[_]
}
