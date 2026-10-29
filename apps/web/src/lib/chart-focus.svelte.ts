/**
 * The bucket a pointer or the keyboard is on, shared by the time charts of one page: charts with the same
 * group draw their crosshair on the same day or week, and the chart that owns the pointer shows the readout.
 */
export const chartFocus = $state<{ group: string | null; index: number | null; owner: string | null }>({
  group: null,
  index: null,
  owner: null,
});
