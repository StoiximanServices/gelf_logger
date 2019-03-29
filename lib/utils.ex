defmodule Utils do
  @moduledoc false

  @epoch :calendar.datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})

  def to_unix({{year, month, day}, {hour, min, sec, milli}}) do
    {{year, month, day}, {hour, min, sec}}
    |> :calendar.datetime_to_gregorian_seconds()
    |> Kernel.-(@epoch)
    |> Kernel.+(milli / 1_000)
    |> Float.round(3)
  end

  def level_to_int(:debug), do: 7
  def level_to_int(:info), do: 6
  def level_to_int(:warn), do: 4
  def level_to_int(:error), do: 3
end
