defmodule JOSEVirtualHSM.NoSuitableKeyFoundError do
  defexception message: "no suitable key has been found"
end

defmodule JOSEVirtualHSM.NoSuitableAlgFoundError do
  defexception message: "no suitable alg has been found"
end

defmodule JOSEVirtualHSM.WorkerError do
  defexception [:reason]

  @impl true
  def message(%{reason: reason}),
    do: "JOSEVirtualHSM worker terminated with reason: #{inspect(reason)}"
end

defmodule JOSEVirtualHSM.DecryptionError do
  defexception message: "the message could not be decrypted"
end
