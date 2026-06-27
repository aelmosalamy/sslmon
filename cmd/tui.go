package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"sslmon/internal/crtsh"
)

// certItem adapts a cached certificate to the bubbles/list interface. The
// default delegate renders Title over Description and filters on FilterValue.
type certItem struct {
	domain string
	cert   crtsh.Cert
}

func (i certItem) Title() string {
	return primaryName(i.cert.CommonName, i.cert.Names)
}

func (i certItem) Description() string {
	return fmt.Sprintf("%s → %s  ·  %s  ·  %s",
		i.cert.NotBefore.Format("2006-01-02"),
		i.cert.NotAfter.Format("2006-01-02"),
		strings.Join(i.cert.Names, ", "),
		i.cert.Issuer)
}

// FilterValue is what "/" searches over: names, common name, issuer and the
// cache bucket the certificate came from.
func (i certItem) FilterValue() string {
	return strings.Join(append(append([]string{}, i.cert.Names...), i.cert.CommonName, i.cert.Issuer, i.domain), " ")
}

var docStyle = lipgloss.NewStyle().Margin(1, 2)

type tuiModel struct {
	list list.Model
}

func (m tuiModel) Init() tea.Cmd { return nil }

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h, v := docStyle.GetFrameSize()
		m.list.SetSize(msg.Width-h, msg.Height-v)
	case tea.KeyMsg:
		// While the filter input is focused, let the list handle every key
		// (including "q"). Otherwise q/esc/ctrl+c quit.
		if m.list.FilterState() != list.Filtering {
			switch msg.String() {
			case "q", "esc", "ctrl+c":
				return m, tea.Quit
			}
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m tuiModel) View() string {
	return docStyle.Render(m.list.View())
}

func runTUI(ctx context.Context, items []certItem) error {
	listItems := make([]list.Item, len(items))
	for i, it := range items {
		listItems[i] = it
	}

	l := list.New(listItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Certificates"
	l.SetStatusBarItemName("certificate", "certificates")
	// Plain case-insensitive substring filtering instead of the default fuzzy
	// matcher, so "/" searches behave like grep.
	l.Filter = substringFilter

	prog := tea.NewProgram(tuiModel{list: l}, tea.WithAltScreen(), tea.WithContext(ctx))
	_, err := prog.Run()
	return err
}

// substringFilter is a list.FilterFunc that keeps items whose FilterValue
// contains the search term (case-insensitive), in their original order.
func substringFilter(term string, targets []string) []list.Rank {
	term = strings.ToLower(term)
	var ranks []list.Rank
	for i, t := range targets {
		if strings.Contains(strings.ToLower(t), term) {
			ranks = append(ranks, list.Rank{Index: i})
		}
	}
	return ranks
}
