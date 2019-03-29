defmodule Backend.AMQP do
  @moduledoc false

  alias Backend.RabbitMQ
  alias Messages.Gelf
  alias Utils

  @host Config.connection_host()
  @file_line [:file, :line]

  def log_event(level, message, timestamp, metadata, channel) do
    level
    |> build_gelf_map(message, timestamp, metadata)
    |> Gelf.new()
    |> Gelf.to_json()
    |> RabbitMQ.publish_gelf(channel)
  end

  defp build_gelf_map(level, message, timestamp, metadata) do
    int_level = Utils.level_to_int(level)
    unix_timestamp = Utils.to_unix(timestamp)

    %{
      full_message: to_string(message),
      host: @host,
      level: int_level,
      short_message: String.slice(message, 0..79),
      timestamp: unix_timestamp
    }
    |> fill_file_line_if_present(metadata)
  end

  defp fill_file_line_if_present(gelf_map, metadata) do
    Enum.reduce(@file_line, gelf_map, fn x, gelf_map ->
      result = Keyword.get(metadata, x)

      case result do
        nil -> Map.put(gelf_map, x, nil)
        _ -> Map.put(gelf_map, x, result)
      end
    end)
  end
end
