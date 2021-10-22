# -*- coding: binary -*-

module Rex
module Powershell
module Exceptions

  class PowershellError < RuntimeError
  end

  class PowershellCommandLengthError < PowershellError
  end

end
end
end

