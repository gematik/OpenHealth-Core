// SPDX-FileCopyrightText: Copyright 2025 gematik GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

pub mod apdu;
pub mod change_reference_data_command;
pub mod error;
pub mod external_authenticate_command;
pub mod general_authenticate_command;
pub mod get_pin_status_command;
pub mod get_random_command;
pub mod health_card_command;
pub mod health_card_status;
pub mod manage_security_environment_command;
pub mod pso_compute_digital_signature_command;
pub mod read_command;
pub mod reset_retry_counter_command;
pub mod reset_retry_counter_with_new_secret_command;
pub mod select_command;
pub mod verify_pin_command;

pub use error::CommandError;
pub use read_command::ReadCommand;
pub use select_command::SelectCommand;
