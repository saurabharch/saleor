from typing import TYPE_CHECKING, List

import graphene
from django.core.exceptions import ValidationError

from ....attribute import AttributeType
from ....attribute import models as attribute_models
from ....core.error_codes import ShopErrorCode
from ....core.permissions import SitePermissions
from ...attribute.types import Attribute
from ...core.mutations import BaseMutation
from ...core.types.common import ShopError
from ...core.utils import get_duplicates_ids
from ...utils import resolve_global_ids_to_primary_keys
from ..types import CategorySettings

if TYPE_CHECKING:
    from ....site.models import SiteSettings


class CategorySettingsInput(graphene.InputObjectType):
    add_attributes = graphene.List(
        graphene.NonNull(graphene.ID),
        description=(
            "List of attribute IDs that should be added to available "
            "category attributes."
        ),
        required=False,
    )
    remove_attributes = graphene.List(
        graphene.NonNull(graphene.ID),
        description=(
            "List of attribute IDs that should be removed from available "
            "category attributes."
        ),
        required=False,
    )


class CategorySettingsUpdate(BaseMutation):
    category_settings = graphene.Field(
        CategorySettings, description="Updated category settings."
    )

    class Arguments:
        input = CategorySettingsInput(
            required=True, description="Fields required to update category settings."
        )

    class Meta:
        description = "Updates category settings."
        permissions = (SitePermissions.MANAGE_SETTINGS,)
        error_type_class = ShopError
        error_type_field = "shop_errors"

    @classmethod
    def perform_mutation(cls, _root, info, **data):
        site_settings = info.context.site.settings
        input = data["input"]
        cleaned_input = cls.clean_input(site_settings, input)
        cls.update_category_settings(site_settings, cleaned_input)
        return cls(category_settings=CategorySettings())

    @classmethod
    def clean_input(cls, site_settings: "SiteSettings", input_data: dict):
        cls.validate_duplicates(input_data)

        remove_attrs = input_data.get("remove_attributes")
        if remove_attrs:
            input_data["remove_attributes"] = cls.get_nodes_or_error(
                remove_attrs, "id", Attribute
            )

        add_attrs = input_data.get("add_attributes")
        if add_attrs:
            _, pks = resolve_global_ids_to_primary_keys(add_attrs, Attribute)
            pks = cls.clean_add_attributes(pks, site_settings)
            input_data["add_attributes"] = attribute_models.Attribute.objects.filter(
                pk__in=pks
            )

        cls.validate_attribute_types(input_data.get("add_attributes", []))
        return input_data

    @staticmethod
    def validate_duplicates(input_data: dict):
        duplicated_ids = get_duplicates_ids(
            input_data.get("add_attributes"), input_data.get("remove_attributes")
        )
        if duplicated_ids:
            error_msg = (
                "The same object cannot be in both list"
                "for adding and removing items."
            )
            raise ValidationError(
                {
                    "input": ValidationError(
                        error_msg,
                        code=ShopErrorCode.DUPLICATED_INPUT_ITEM.value,
                        params={"attributes": list(duplicated_ids)},
                    )
                }
            )

    @staticmethod
    def clean_add_attributes(attr_ids: List[int], site_settings: "SiteSettings"):
        # drop attributes that are already assigned
        attr_ids = {int(id) for id in attr_ids}
        assigned_attr_ids = attribute_models.AttributeCategory.objects.filter(
            site_settings=site_settings, attribute_id__in=attr_ids
        ).values_list("attribute_id", flat=True)
        return set(attr_ids) - set(assigned_attr_ids)

    @staticmethod
    def validate_attribute_types(attributes: List[attribute_models.Attribute]):
        # only page attributes can be set as category attributes
        invalid_attrs = [
            attr for attr in attributes if attr.type != AttributeType.PAGE_TYPE
        ]
        if invalid_attrs:
            attr_ids = [
                graphene.Node.to_global_id("Attribute", attr.pk)
                for attr in invalid_attrs
            ]
            raise ValidationError(
                {
                    "input": ValidationError(
                        "Only Page attributes can be set as category attributes.",
                        code=ShopErrorCode.INVALID.value,
                        params={"attributes": attr_ids},
                    )
                }
            )

    @staticmethod
    def update_category_settings(site_settings: "SiteSettings", cleaned_input: dict):
        remove_attr = cleaned_input.get("remove_attributes")
        add_attr = cleaned_input.get("add_attributes")
        if remove_attr:
            site_settings.category_attributes.filter(
                attribute_id__in=remove_attr
            ).delete()
        if add_attr:
            attribute_models.AttributeCategory.objects.bulk_create(
                [
                    attribute_models.AttributeCategory(
                        site_settings=site_settings, attribute=attr
                    )
                    for attr in add_attr
                ]
            )
