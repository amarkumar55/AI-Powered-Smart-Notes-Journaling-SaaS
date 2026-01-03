# planner/serializers.py
from .models import PlannerEntry
from rest_framework import serializers


class PlannerEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = PlannerEntry
        fields = [
            "id", "date", "start_time", "end_time", "is_all_day",
            "title", "description", "location",
            "reminder_minutes_before", "want_notification",
            "status", "created_at", "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]
        

    def validate(self, attrs):
        user = self.context["request"].user
        is_all_day = attrs.get("is_all_day", getattr(self.instance, "is_all_day", False))
        start_time = attrs.get("start_time", getattr(self.instance, "start_time", None))
        end_time = attrs.get("end_time", getattr(self.instance, "end_time", None))
        date = attrs.get("date", getattr(self.instance, "date", None))

        # --- Time validation ---
        if not is_all_day:
            if start_time is None or end_time is None:
                raise serializers.ValidationError("Start time and end time are required for non all-day entries.")
            if end_time <= start_time:
                raise serializers.ValidationError("End time must be after Start time.")
        else:
            # Normalize all-day entries: force times to None
            attrs["start_time"] = None
            attrs["end_time"] = None

        # --- Prevent overlapping times (for same user & date) ---
        if date and not is_all_day:
            qs = PlannerEntry.objects.filter(user=user, date=date)

            if self.instance:
                qs = qs.exclude(id=self.instance.id)

            for other in qs:
                if other.start_time and other.end_time:
                    # check overlap
                    if max(start_time, other.start_time) < min(end_time, other.end_time):
                        raise serializers.ValidationError(
                            f"Time slot overlaps with '{other.title}' ({other.start_time} - {other.end_time})."
                        )

        return attrs
