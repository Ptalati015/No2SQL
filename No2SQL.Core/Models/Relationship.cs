
namespace No2SQL.Core.Models;
public class Relationship
{
    public string FromCollection { get; set; } = string.Empty;
    public string ToCollection { get; set; } = string.Empty;
    public string FieldName { get; set; } = string.Empty;
    public double Confidence { get; set; }
    public string? ToField { get; set; }
}
