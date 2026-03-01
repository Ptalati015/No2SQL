using System;
using System.Collections.Generic;
using System.Text;

namespace No2SQL.Sql.Models
{
    public class UserRelationshipOverride
{
    public string FromCollection { get; set; }
    public string FromField { get; set; }
    public string ToCollection { get; set; }
    public string ToField { get; set; } 
}
}
