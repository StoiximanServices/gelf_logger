defmodule Messages.Gelf do
  @moduledoc false

  @_facility 1
  @version "1.1"

  defstruct [
    :file,
    :full_message,
    :host,
    :level,
    :line,
    :short_message,
    :timestamp,
    _facility: @_facility,
    version: @version
  ]

  @type t :: %__MODULE__{
          _facility: String.t() | pos_integer,
          file: String.t() | nil,
          full_message: String.t(),
          host: String.t(),
          level: pos_integer,
          line: non_neg_integer | nil,
          short_message: String.t(),
          timestamp: non_neg_integer,
          version: String.t()
        }

  @spec new(map) :: t()
  def new(data) do
    %{
      file: file,
      full_message: full_message,
      host: host,
      level: level,
      line: line,
      short_message: short_message,
      timestamp: timestamp
    } = data

    %__MODULE__{
      file: file,
      full_message: full_message,
      host: host,
      level: level,
      line: line,
      short_message: short_message,
      timestamp: timestamp
    }
  end

  def to_json(%__MODULE__{} = gelf_message), do: Poison.encode!(gelf_message)
end
