rule SUSP_Private_Network_Error
{
    meta:
        author = "Manuel"
        description = "Detects files referencing the /app/index.php PHP endpoint with specific parameters or the denial error message."
        date = "2025-10-09"

    strings:
        $path = "/app/index.php" ascii wide
        $param_userid = "userid=" ascii wide
        $param_ue = "&ue=" ascii wide
        $denial_string = "THE REQUEST WAS DENIED: MAKE SURE YOU ARE NOT CONNECTED TO A PRIVATE NETWORK" ascii wide nocase

    condition:
        ( $path and ( $param_userid or $param_ue ) ) or
        ($denial_string)
}
