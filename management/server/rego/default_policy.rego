package netbird

# all rules for peer connectivity and firewall
all[rule] {
  rule := array.concat(
    rules_from_groups(["All"], "dst", "accept", ""),
    rules_from_groups(["All"], "src", "accept", ""))[_]
}
