import { createTheme } from '@mui/material/styles'

export const brand = '#0fa5a0'

export const theme = createTheme({
  palette: {
    primary: { main: brand, contrastText: '#fff' },
    secondary: { main: '#3b6fd6' },
    error: { main: '#e5484d' },
    warning: { main: '#f59e0b' },
    background: { default: '#f3f6f8', paper: '#ffffff' },
    text: { primary: '#1d2b36', secondary: '#5c6b77' },
  },
  shape: { borderRadius: 8 },
  typography: {
    fontFamily: 'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
    fontSize: 13,
    h5: { fontWeight: 700 },
    h6: { fontWeight: 700, fontSize: 16 },
    button: { textTransform: 'none', fontWeight: 600 },
  },
  components: {
    MuiPaper: { styleOverrides: { root: { boxShadow: '0 1px 3px rgba(16,24,40,.06)' } } },
    MuiCard: { defaultProps: { variant: 'outlined' } },
    MuiButton: { defaultProps: { disableElevation: true } },
    MuiTableCell: {
      styleOverrides: {
        head: { fontWeight: 600, color: '#5c6b77', backgroundColor: '#f7f9fa', whiteSpace: 'nowrap' },
        root: { borderColor: '#eef1f3' },
      },
    },
    MuiTextField: { defaultProps: { size: 'small' } },
    MuiSelect: { defaultProps: { size: 'small' } },
    MuiChip: { styleOverrides: { root: { fontWeight: 600 } } },
    MuiTab: { styleOverrides: { root: { minHeight: 44 } } },
  },
})
