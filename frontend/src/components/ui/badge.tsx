import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset",
  {
    variants: {
      variant: {
        critical: "bg-red-50 text-red-700 ring-red-600/20",
        high:     "bg-orange-50 text-orange-700 ring-orange-600/20",
        medium:   "bg-yellow-50 text-yellow-700 ring-yellow-600/20",
        low:      "bg-blue-50 text-blue-700 ring-blue-600/20",
        informational: "bg-gray-50 text-gray-600 ring-gray-500/20",
        // status
        open:         "bg-slate-50 text-slate-700 ring-slate-600/20",
        in_progress:  "bg-indigo-50 text-indigo-700 ring-indigo-600/20",
        remediated:   "bg-green-50 text-green-700 ring-green-600/20",
        accepted:     "bg-gray-50 text-gray-600 ring-gray-500/20",
        false_positive: "bg-purple-50 text-purple-700 ring-purple-600/20",
        // triage priority
        immediate:  "bg-red-100 text-red-800 ring-red-600/20",
        this_week:  "bg-orange-100 text-orange-800 ring-orange-600/20",
        this_month: "bg-yellow-100 text-yellow-800 ring-yellow-600/20",
        monitor:    "bg-blue-100 text-blue-800 ring-blue-600/20",
        accept:     "bg-gray-100 text-gray-600 ring-gray-500/20",
        // generic
        default:  "bg-gray-100 text-gray-700 ring-gray-600/20",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

type BadgeVariant = VariantProps<typeof badgeVariants>["variant"];

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant;
}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}
