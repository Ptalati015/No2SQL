
namespace No2SQL.Core.Models;
public class Relationship
{
    public string FromCollection { get; set; }
    public string ToCollection { get; set; }
    public string FieldName { get; set; }
    public double Confidence { get; set; }
}
