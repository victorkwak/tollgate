//! A unified line diff for the settings edit `install` and `uninstall`
//! show before they ask (R95c, R96). Settings files are small, so a plain
//! longest-common-subsequence table is enough.

/// One line of the edit script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op<'a> {
    Same(&'a str),
    Del(&'a str),
    Add(&'a str),
}

fn script<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<Op<'a>> {
    let (n, m) = (a.len(), b.len());
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut ops = Vec::with_capacity(n + m);
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            ops.push(Op::Same(a[i]));
            i += 1;
            j += 1;
        } else if i < n && (j == m || lcs[i + 1][j] >= lcs[i][j + 1]) {
            ops.push(Op::Del(a[i]));
            i += 1;
        } else {
            ops.push(Op::Add(b[j]));
            j += 1;
        }
    }
    ops
}

/// A unified diff of `old` and `new` with `context` lines around each
/// change; empty when they are equal.
#[must_use]
pub fn unified(old: &str, new: &str, old_name: &str, new_name: &str, context: usize) -> String {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let ops = script(&a, &b);
    if ops.iter().all(|o| matches!(o, Op::Same(_))) {
        return String::new();
    }
    let mut out = format!("--- {old_name}\n+++ {new_name}\n");
    // Indexes of changed ops, grouped into hunks with their context.
    let changed: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, o)| !matches!(o, Op::Same(_)))
        .map(|(k, _)| k)
        .collect();
    let mut k = 0;
    while k < changed.len() {
        let start = changed[k].saturating_sub(context);
        let mut end = changed[k];
        while k + 1 < changed.len() && changed[k + 1] <= end + 2 * context + 1 {
            k += 1;
            end = changed[k];
        }
        let end = (end + context + 1).min(ops.len());
        // Line numbers at `start`.
        let (mut oi, mut ni) = (1usize, 1usize);
        for o in &ops[..start] {
            match o {
                Op::Same(_) => {
                    oi += 1;
                    ni += 1;
                }
                Op::Del(_) => oi += 1,
                Op::Add(_) => ni += 1,
            }
        }
        let olen = ops[start..end]
            .iter()
            .filter(|o| !matches!(o, Op::Add(_)))
            .count();
        let nlen = ops[start..end]
            .iter()
            .filter(|o| !matches!(o, Op::Del(_)))
            .count();
        out.push_str(&format!("@@ -{oi},{olen} +{ni},{nlen} @@\n"));
        for o in &ops[start..end] {
            let (sign, line) = match o {
                Op::Same(l) => (' ', l),
                Op::Del(l) => ('-', l),
                Op::Add(l) => ('+', l),
            };
            out.push(sign);
            out.push_str(line);
            out.push('\n');
        }
        k += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_texts_give_no_diff() {
        assert_eq!(unified("a\nb\n", "a\nb\n", "x", "y", 3), "");
    }

    #[test]
    fn hunks_show_changes_with_context() {
        let old = "1\n2\n3\n4\n5\n6\n7\n8\n9\n";
        let new = "1\n2\n3\nfour\n5\n6\n7\n8\n9\nten\n";
        let d = unified(old, new, "old", "new", 1);
        assert_eq!(
            d,
            "--- old\n+++ new\n@@ -3,3 +3,3 @@\n 3\n-4\n+four\n 5\n@@ -9,1 +9,2 @@\n 9\n+ten\n"
        );
    }
}
